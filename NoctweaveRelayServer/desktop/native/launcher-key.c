#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { launcher_key_bytes = 32 };

#ifndef LAUNCHER_KEY_SERVICE
#define LAUNCHER_KEY_SERVICE "org.noctweave.relay-desktop.launcher-state.v1"
#endif
#ifndef LAUNCHER_KEY_ACCOUNT
#define LAUNCHER_KEY_ACCOUNT "device-key"
#endif

static void wipe_bytes(void *pointer, size_t count) {
    volatile uint8_t *bytes = pointer;
    while (count-- > 0) *bytes++ = 0;
}

static CFMutableDictionaryRef key_query(void) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    if (query == NULL) return NULL;
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR(LAUNCHER_KEY_SERVICE));
    CFDictionarySetValue(query, kSecAttrAccount, CFSTR(LAUNCHER_KEY_ACCOUNT));
    CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
    return query;
}

static int write_key(const uint8_t *bytes) {
    size_t offset = 0;
    while (offset < launcher_key_bytes) {
        ssize_t count = write(STDOUT_FILENO, bytes + offset, launcher_key_bytes - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 1;
        offset += (size_t)count;
    }
    return 0;
}

static int load_key(CFMutableDictionaryRef query, bool *missing) {
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUISkip);
    CFTypeRef item = NULL;
    OSStatus status = SecItemCopyMatching(query, &item);
    CFDictionaryRemoveValue(query, kSecMatchLimit);
    CFDictionaryRemoveValue(query, kSecReturnData);
    CFDictionaryRemoveValue(query, kSecUseAuthenticationUI);
    if (status == errSecItemNotFound) {
        *missing = true;
        return 0;
    }
    if (status != errSecSuccess || item == NULL || CFGetTypeID(item) != CFDataGetTypeID()) {
        if (item != NULL) CFRelease(item);
        fprintf(stderr, "launcher Keychain read failed (%d)\n", (int)status);
        return 1;
    }
    CFDataRef data = (CFDataRef)item;
    if (CFDataGetLength(data) != launcher_key_bytes || CFDataGetBytePtr(data) == NULL) {
        CFRelease(item);
        fprintf(stderr, "launcher Keychain key has an invalid length\n");
        return 1;
    }
    int result = write_key(CFDataGetBytePtr(data));
    CFRelease(item);
    if (result != 0) fprintf(stderr, "launcher key pipe failed\n");
    return result;
}

int main(int argc, char **argv) {
    #ifdef LAUNCHER_KEY_TEST_ALLOW_DELETE
    bool delete_test_item = argc == 2 && strcmp(argv[1], "--delete") == 0;
    if (argc != 1 && !delete_test_item) return 2;
    #else
    (void)argv;
    if (argc != 1) return 2;
    #endif
    CFMutableDictionaryRef query = key_query();
    if (query == NULL) return 1;
    #ifdef LAUNCHER_KEY_TEST_ALLOW_DELETE
    if (delete_test_item) {
        OSStatus status = SecItemDelete(query);
        CFRelease(query);
        return status == errSecSuccess || status == errSecItemNotFound ? 0 : 1;
    }
    #endif
    bool missing = false;
    int result = load_key(query, &missing);
    if (result != 0 || !missing) {
        CFRelease(query);
        return result;
    }

    uint8_t bytes[launcher_key_bytes];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(bytes), bytes) != errSecSuccess) {
        CFRelease(query);
        fprintf(stderr, "launcher key generation failed\n");
        return 1;
    }
    CFDataRef data = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault, bytes, sizeof(bytes), kCFAllocatorNull
    );
    if (data == NULL) {
        wipe_bytes(bytes, sizeof(bytes));
        CFRelease(query);
        return 1;
    }
    CFDictionarySetValue(query, kSecValueData, data);
    CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    OSStatus status = SecItemAdd(query, NULL);
    CFRelease(data);
    CFDictionaryRemoveValue(query, kSecValueData);
    CFDictionaryRemoveValue(query, kSecAttrAccessible);
    if (status == errSecDuplicateItem) {
        wipe_bytes(bytes, sizeof(bytes));
        result = load_key(query, &missing);
    } else if (status == errSecSuccess) {
        result = write_key(bytes);
        wipe_bytes(bytes, sizeof(bytes));
    } else {
        wipe_bytes(bytes, sizeof(bytes));
        fprintf(stderr, "launcher Keychain create failed (%d)\n", (int)status);
        result = 1;
    }
    CFRelease(query);
    return result;
}
