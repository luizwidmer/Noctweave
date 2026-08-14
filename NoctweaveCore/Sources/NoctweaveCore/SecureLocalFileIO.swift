import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum SecureLocalFileIOError: Error {
    case notFound
    case inaccessible
    case notRegular
    case tooLarge
    case changedDuringRead
    case unsafeDirectory
}

/// Descriptor-based local persistence for protocol state. The final path
/// component is never followed, reads stay inside a caller-provided bound, and
/// private writes are committed from a mode-0600 temporary file in a verified
/// mode-0700 directory.
enum SecureLocalFileIO {
    static func readBoundedRegularFile(
        at url: URL,
        maximumBytes: Int,
        allowEmpty: Bool = false,
        requirePrivateOwner: Bool = false
    ) throws -> Data {
        guard maximumBytes >= 0, maximumBytes < Int.max else {
            throw SecureLocalFileIOError.tooLarge
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
            throw SecureLocalFileIOError.inaccessible
        }
        defer { _ = close(directory) }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else {
            throw SecureLocalFileIOError.inaccessible
        }
        let descriptor: Int32 = name.withCString { filename in
            openat(
                directory,
                filename,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            )
        }
        guard descriptor >= 0 else {
            throw errno == ENOENT ? SecureLocalFileIOError.notFound : .inaccessible
        }
        defer { _ = close(descriptor) }

        let before = try validateRegularDescriptor(
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
            guard remaining > 0 else { throw SecureLocalFileIOError.tooLarge }
            let requested = min(buffer.count, remaining)
            let count = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                return read(descriptor, base, requested)
            }
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw SecureLocalFileIOError.inaccessible }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
            guard data.count <= maximumBytes else {
                throw SecureLocalFileIOError.tooLarge
            }
        }

        var after = stat()
        guard fstat(descriptor, &after) == 0,
              sameFileAndVersion(before, after),
              data.count == Int(after.st_size),
              allowEmpty || !data.isEmpty else {
            throw SecureLocalFileIOError.changedDuringRead
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
        guard descriptor >= 0 else { throw SecureLocalFileIOError.unsafeDirectory }
        defer { _ = close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_uid == geteuid(),
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
              fchmod(descriptor, mode_t(0o700)) == 0 else {
            throw SecureLocalFileIOError.unsafeDirectory
        }
    }

    static func writeAtomicPrivateFile(
        _ data: Data,
        to fileURL: URL,
        maximumBytes: Int,
        allowEmpty: Bool = false,
        excludedFromBackup: Bool = false
    ) throws {
        guard data.count <= maximumBytes, allowEmpty || !data.isEmpty else {
            throw SecureLocalFileIOError.tooLarge
        }
        let directoryURL = fileURL.deletingLastPathComponent()
        try ensurePrivateDirectory(at: directoryURL)
        let directory: Int32 = directoryURL.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard directory >= 0 else { throw SecureLocalFileIOError.unsafeDirectory }
        defer { _ = close(directory) }

        let name = fileURL.lastPathComponent
        guard isSafeFilename(name) else {
            throw SecureLocalFileIOError.inaccessible
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
        guard descriptor >= 0 else { throw SecureLocalFileIOError.inaccessible }
        var descriptorIsOpen = true
        var temporaryExists = true
        defer {
            if descriptorIsOpen { _ = close(descriptor) }
            if temporaryExists {
                temporaryName.withCString { _ = unlinkat(directory, $0, 0) }
            }
        }

        guard fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        #if os(iOS) && !targetEnvironment(simulator)
        // Darwin content-protection class A is NSFileProtectionComplete.
        guard fcntl(descriptor, F_SETPROTECTIONCLASS, 1) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        #endif
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
                guard count > 0 else { throw SecureLocalFileIOError.inaccessible }
                written += count
            }
        }
        guard fsync(descriptor) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        var committedStatus = stat()
        guard fstat(descriptor, &committedStatus) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }

        let renameResult = temporaryName.withCString { temporary in
            name.withCString { destination in
                renameat(directory, temporary, directory, destination)
            }
        }
        guard renameResult == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        temporaryExists = false
        #if canImport(Darwin)
        if excludedFromBackup {
            try setExcludedFromBackup(
                at: fileURL,
                directory: directory,
                name: name,
                expected: committedStatus
            )
        }
        #endif
        guard fsync(descriptor) == 0, fsync(directory) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        guard close(descriptor) == 0 else {
            descriptorIsOpen = false
            throw SecureLocalFileIOError.inaccessible
        }
        descriptorIsOpen = false
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
            throw SecureLocalFileIOError.unsafeDirectory
        }
        defer { _ = close(directory) }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else {
            throw SecureLocalFileIOError.inaccessible
        }
        let result: Int32 = name.withCString { filename in
            unlinkat(directory, filename, 0)
        }
        guard result == 0 || errno == ENOENT else {
            throw SecureLocalFileIOError.inaccessible
        }
        if result == 0, fsync(directory) != 0 {
            throw SecureLocalFileIOError.inaccessible
        }
    }

    static func replaceFile(at destinationURL: URL, with sourceURL: URL) throws {
        let destinationDirectory = destinationURL.deletingLastPathComponent()
            .standardizedFileURL
        let sourceDirectory = sourceURL.deletingLastPathComponent()
            .standardizedFileURL
        guard destinationDirectory.path == sourceDirectory.path else {
            throw SecureLocalFileIOError.unsafeDirectory
        }
        let directory: Int32 = destinationDirectory
            .withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }
                return open(
                    path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
            }
        guard directory >= 0 else {
            throw SecureLocalFileIOError.unsafeDirectory
        }
        defer { _ = close(directory) }
        let sourceName = sourceURL.lastPathComponent
        let destinationName = destinationURL.lastPathComponent
        guard isSafeFilename(sourceName), isSafeFilename(destinationName) else {
            throw SecureLocalFileIOError.inaccessible
        }
        let result = sourceName.withCString { source in
            destinationName.withCString { destination in
                renameat(directory, source, directory, destination)
            }
        }
        guard result == 0, fsync(directory) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
    }

    static func hardenAndSynchronizePrivateFile(
        at url: URL,
        excludedFromBackup: Bool = false
    ) throws {
        let directory: Int32 = url.deletingLastPathComponent()
            .withUnsafeFileSystemRepresentation { path in
                guard let path else { return -1 }
                return open(
                    path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
                )
            }
        guard directory >= 0 else {
            throw SecureLocalFileIOError.unsafeDirectory
        }
        defer { _ = close(directory) }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else {
            throw SecureLocalFileIOError.inaccessible
        }
        let descriptor: Int32 = name.withCString { filename in
            openat(directory, filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        defer { _ = close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_uid == geteuid(),
              fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw SecureLocalFileIOError.notRegular
        }
        #if os(iOS) && !targetEnvironment(simulator)
        guard fcntl(descriptor, F_SETPROTECTIONCLASS, 1) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        #endif
        #if canImport(Darwin)
        if excludedFromBackup {
            try setExcludedFromBackup(
                at: url,
                directory: directory,
                name: name,
                expected: status
            )
        }
        #endif
        guard fsync(descriptor) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
    }

    #if canImport(Darwin)
    /// Foundation exposes backup exclusion only as a URL resource property.
    /// Keep the intended file open and verify its identity through both the
    /// anchored directory descriptor and the public path around that call so
    /// a pathname substitution fails closed instead of silently weakening the
    /// persisted state's backup policy.
    private static func setExcludedFromBackup(
        at url: URL,
        directory: Int32,
        name: String,
        expected: stat
    ) throws {
        guard try pathIdentity(at: url).map({ sameFileIdentity($0, expected) }) == true else {
            throw SecureLocalFileIOError.inaccessible
        }

        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        do {
            try mutableURL.setResourceValues(values)
            let applied = try mutableURL.resourceValues(
                forKeys: [.isExcludedFromBackupKey]
            )
            guard applied.isExcludedFromBackup == true else {
                throw SecureLocalFileIOError.inaccessible
            }
        } catch let error as SecureLocalFileIOError {
            throw error
        } catch {
            throw SecureLocalFileIOError.inaccessible
        }

        guard try pathIdentity(at: url).map({ sameFileIdentity($0, expected) }) == true else {
            throw SecureLocalFileIOError.inaccessible
        }
        let verificationDescriptor: Int32 = name.withCString { filename in
            openat(directory, filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard verificationDescriptor >= 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        defer { _ = close(verificationDescriptor) }
        var verified = stat()
        guard fstat(verificationDescriptor, &verified) == 0,
              sameFileIdentity(verified, expected),
              (verified.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              verified.st_uid == geteuid(),
              (verified.st_mode & mode_t(0o077)) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
    }

    private static func pathIdentity(at url: URL) throws -> stat? {
        var status = stat()
        let result: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return lstat(path, &status)
        }
        if result == 0 { return status }
        if errno == ENOENT { return nil }
        throw SecureLocalFileIOError.inaccessible
    }
    #endif

    /// Pins a private regular file while a path-only SQLite API opens it, then
    /// verifies that the anchored name still resolves to the same inode.
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
        guard directory >= 0 else { throw SecureLocalFileIOError.unsafeDirectory }
        defer { _ = close(directory) }
        let resolvedDirectoryPath: String? = directoryURL.withUnsafeFileSystemRepresentation { path in
            guard let path, let resolved = realpath(path, nil) else { return nil }
            defer { free(resolved) }
            return String(cString: resolved)
        }
        guard let resolvedDirectoryPath else {
            throw SecureLocalFileIOError.unsafeDirectory
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
              sameFileIdentity(pinnedDirectory, resolvedDirectory) else {
            throw SecureLocalFileIOError.unsafeDirectory
        }
        let name = url.lastPathComponent
        guard isSafeFilename(name) else { throw SecureLocalFileIOError.inaccessible }
        let descriptor: Int32 = name.withCString { filename in
            openat(directory, filename, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        }
        guard descriptor >= 0 else { throw SecureLocalFileIOError.inaccessible }
        defer { _ = close(descriptor) }
        var expected = stat()
        guard fstat(descriptor, &expected) == 0,
              (expected.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              expected.st_uid == geteuid(),
              fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw SecureLocalFileIOError.notRegular
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
              sameFileIdentity(expected, descriptorAfter),
              sameFileIdentity(expected, anchoredAfter),
              (anchoredAfter.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              anchoredAfter.st_uid == geteuid(),
              (anchoredAfter.st_mode & mode_t(0o077)) == 0 else {
            throw SecureLocalFileIOError.inaccessible
        }
        return result
    }

    private static func isSafeFilename(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." && !value.contains("/")
    }

    private static func validateRegularDescriptor(
        _ descriptor: Int32,
        maximumBytes: Int,
        allowEmpty: Bool,
        requirePrivateOwner: Bool
    ) throws -> stat {
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              status.st_size >= 0 else {
            throw SecureLocalFileIOError.notRegular
        }
        guard UInt64(status.st_size) <= UInt64(maximumBytes) else {
            throw SecureLocalFileIOError.tooLarge
        }
        guard allowEmpty || status.st_size > 0 else {
            throw SecureLocalFileIOError.notRegular
        }
        if requirePrivateOwner {
            guard status.st_uid == geteuid(),
                  (status.st_mode & mode_t(0o077)) == 0 else {
                throw SecureLocalFileIOError.notRegular
            }
        }
        return status
    }

    private static func sameFileAndVersion(_ lhs: stat, _ rhs: stat) -> Bool {
        sameFileIdentity(lhs, rhs)
            && lhs.st_size == rhs.st_size
            && modificationTime(lhs) == modificationTime(rhs)
            && changeTime(lhs) == changeTime(rhs)
    }

    private static func sameFileIdentity(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino
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
