import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum RelayServerSecureFileIOError: Error {
    case notFound
    case inaccessible
    case notRegular
    case tooLarge
    case changedDuringRead
    case unsafeDirectory
}

/// No-follow, bounded persistence for relay-owned configuration, identity,
/// and hosted-object files.
enum RelayServerSecureFileIO {
    static func read(
        from url: URL,
        maximumBytes: Int,
        allowEmpty: Bool = false,
        requirePrivateOwner: Bool = true
    ) throws -> Data {
        guard maximumBytes >= 0, maximumBytes < Int.max else {
            throw RelayServerSecureFileIOError.tooLarge
        }
        let directory: Int32 = url.deletingLastPathComponent()
            .withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }
                return open(
                    path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
            }
        guard directory >= 0 else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        defer { _ = close(directory) }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        let descriptor: Int32 = name.withCString { filename in
            openat(
                directory,
                filename,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard descriptor >= 0 else {
            throw errno == ENOENT ? RelayServerSecureFileIOError.notFound : .inaccessible
        }
        defer { _ = close(descriptor) }

        let before = try validate(
            descriptor,
            maximumBytes: maximumBytes,
            allowEmpty: allowEmpty,
            requirePrivateOwner: requirePrivateOwner
        )
        var data = Data()
        data.reserveCapacity(min(Int(before.st_size), maximumBytes))
        var buffer = [UInt8](
            repeating: 0,
            count: max(1, min(64 * 1_024, maximumBytes + 1))
        )
        while true {
            let remaining = maximumBytes + 1 - data.count
            guard remaining > 0 else { throw RelayServerSecureFileIOError.tooLarge }
            let requested = min(buffer.count, remaining)
            let count = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                #if canImport(Darwin)
                return Darwin.read(descriptor, base, requested)
                #else
                return Glibc.read(descriptor, base, requested)
                #endif
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw RelayServerSecureFileIOError.inaccessible }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
            guard data.count <= maximumBytes else {
                throw RelayServerSecureFileIOError.tooLarge
            }
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              sameFileAndVersion(before, after),
              data.count == Int(after.st_size),
              allowEmpty || !data.isEmpty else {
            throw RelayServerSecureFileIOError.changedDuringRead
        }
        return data
    }

    static func ensurePrivateDirectory(at url: URL) throws {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let descriptor: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw RelayServerSecureFileIOError.unsafeDirectory
        }
        defer { _ = close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              fchmod(descriptor, mode_t(0o700)) == 0 else {
            throw RelayServerSecureFileIOError.unsafeDirectory
        }
    }

    static func writePrivate(
        _ data: Data,
        to fileURL: URL,
        maximumBytes: Int,
        allowEmpty: Bool = false
    ) throws {
        guard data.count <= maximumBytes, allowEmpty || !data.isEmpty else {
            throw RelayServerSecureFileIOError.tooLarge
        }
        let directoryURL = fileURL.deletingLastPathComponent()
        try ensurePrivateDirectory(at: directoryURL)
        let directory: Int32 = directoryURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard directory >= 0 else {
            throw RelayServerSecureFileIOError.unsafeDirectory
        }
        defer { _ = close(directory) }

        let name = fileURL.lastPathComponent
        guard isSafeFilename(name) else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        let temporaryName = ".\(name).\(UUID().uuidString.lowercased()).tmp"
        let descriptor: Int32 = temporaryName.withCString { temporary in
            openat(
                directory,
                temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0 else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        var descriptorIsOpen = true
        var temporaryExists = true
        defer {
            if descriptorIsOpen { _ = close(descriptor) }
            if temporaryExists {
                temporaryName.withCString { _ = unlinkat(directory, $0, 0) }
            }
        }

        guard fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var written = 0
            while written < raw.count {
                let count = write(
                    descriptor,
                    base.advanced(by: written),
                    raw.count - written
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else {
                    throw RelayServerSecureFileIOError.inaccessible
                }
                written += count
            }
        }
        guard fsync(descriptor) == 0 else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        guard close(descriptor) == 0 else {
            descriptorIsOpen = false
            throw RelayServerSecureFileIOError.inaccessible
        }
        descriptorIsOpen = false

        let renameResult = temporaryName.withCString { temporary in
            name.withCString { destination in
                renameat(directory, temporary, directory, destination)
            }
        }
        guard renameResult == 0, fsync(directory) == 0 else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        temporaryExists = false
    }

    static func unlinkIfPresent(at url: URL) throws {
        let directory: Int32 = url.deletingLastPathComponent()
            .withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }
                return open(
                    path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
            }
        guard directory >= 0 else {
            throw RelayServerSecureFileIOError.unsafeDirectory
        }
        defer { _ = close(directory) }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        let result: Int32 = name.withCString { filename in
            unlinkat(directory, filename, 0)
        }
        guard result == 0 || errno == ENOENT else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        if result == 0, fsync(directory) != 0 {
            throw RelayServerSecureFileIOError.inaccessible
        }
    }

    static func withPreparedPrivateSQLiteFile<T>(
        at url: URL,
        _ body: (String) throws -> T
    ) throws -> T {
        let directoryURL = url.deletingLastPathComponent()
        try ensurePrivateDirectory(at: directoryURL)
        let directory: Int32 = directoryURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard directory >= 0 else { throw RelayServerSecureFileIOError.unsafeDirectory }
        defer { _ = close(directory) }
        let resolvedDirectoryPath: String? = directoryURL.withUnsafeFileSystemRepresentation { path in
            guard let path, let resolved = realpath(path, nil) else { return nil }
            defer { free(resolved) }
            return String(cString: resolved)
        }
        guard let resolvedDirectoryPath else {
            throw RelayServerSecureFileIOError.unsafeDirectory
        }
        let resolvedDirectoryURL = URL(
            fileURLWithPath: resolvedDirectoryPath,
            isDirectory: true
        )
        var pinnedDirectory = stat()
        var resolvedDirectory = stat()
        let resolvedDirectoryResult: Int32 = resolvedDirectoryURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return stat(path, &resolvedDirectory)
        }
        guard fstat(directory, &pinnedDirectory) == 0,
              resolvedDirectoryResult == 0,
              pinnedDirectory.st_dev == resolvedDirectory.st_dev,
              pinnedDirectory.st_ino == resolvedDirectory.st_ino else {
            throw RelayServerSecureFileIOError.unsafeDirectory
        }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else { throw RelayServerSecureFileIOError.inaccessible }
        let descriptor: Int32 = name.withCString { filename in
            openat(directory, filename, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        }
        guard descriptor >= 0 else { throw RelayServerSecureFileIOError.inaccessible }
        defer { _ = close(descriptor) }
        var expected = stat()
        guard fstat(descriptor, &expected) == 0,
              (expected.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              expected.st_uid == geteuid(),
              fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw RelayServerSecureFileIOError.notRegular
        }
        let sqlitePath = resolvedDirectoryURL.appendingPathComponent(name).path
        let result = try body(sqlitePath)
        var descriptorAfter = stat()
        var anchoredAfter = stat()
        let anchorResult: Int32 = name.withCString { filename in
            fstatat(directory, filename, &anchoredAfter, AT_SYMLINK_NOFOLLOW)
        }
        guard fstat(descriptor, &descriptorAfter) == 0,
              anchorResult == 0,
              expected.st_dev == descriptorAfter.st_dev,
              expected.st_ino == descriptorAfter.st_ino,
              expected.st_dev == anchoredAfter.st_dev,
              expected.st_ino == anchoredAfter.st_ino,
              (anchoredAfter.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              anchoredAfter.st_uid == geteuid(),
              (anchoredAfter.st_mode & mode_t(0o077)) == 0 else {
            throw RelayServerSecureFileIOError.inaccessible
        }
        return result
    }

    private static func isSafeFilename(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." && !value.contains("/")
    }

    private static func validate(
        _ descriptor: Int32,
        maximumBytes: Int,
        allowEmpty: Bool,
        requirePrivateOwner: Bool
    ) throws -> stat {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_size >= 0 else {
            throw RelayServerSecureFileIOError.notRegular
        }
        guard UInt64(status.st_size) <= UInt64(maximumBytes) else {
            throw RelayServerSecureFileIOError.tooLarge
        }
        guard allowEmpty || status.st_size > 0 else {
            throw RelayServerSecureFileIOError.notRegular
        }
        if requirePrivateOwner {
            guard status.st_uid == geteuid(),
                  (status.st_mode & mode_t(0o077)) == 0 else {
                throw RelayServerSecureFileIOError.notRegular
            }
        }
        return status
    }

    private static func sameFileAndVersion(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev
            && lhs.st_ino == rhs.st_ino
            && lhs.st_size == rhs.st_size
            && modificationTime(lhs) == modificationTime(rhs)
            && changeTime(lhs) == changeTime(rhs)
    }

    private static func modificationTime(_ value: stat) -> [Int64] {
        #if canImport(Darwin)
        [Int64(value.st_mtimespec.tv_sec), Int64(value.st_mtimespec.tv_nsec)]
        #else
        [Int64(value.st_mtim.tv_sec), Int64(value.st_mtim.tv_nsec)]
        #endif
    }

    private static func changeTime(_ value: stat) -> [Int64] {
        #if canImport(Darwin)
        [Int64(value.st_ctimespec.tv_sec), Int64(value.st_ctimespec.tv_nsec)]
        #else
        [Int64(value.st_ctim.tv_sec), Int64(value.st_ctim.tv_nsec)]
        #endif
    }
}
