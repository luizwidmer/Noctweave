// SPDX-License-Identifier: AGPL-3.0-or-later

#include <oqs/oqs.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *program) {
	fprintf(stderr,
	        "Usage:\n"
	        "  %s sig-keygen <public-key> <secret-key>\n"
	        "  %s sig-sign <secret-key> <message> <signature>\n"
	        "  %s sig-verify <public-key> <message> <signature>\n"
	        "  %s kem-keygen <public-key> <secret-key>\n"
	        "  %s kem-encaps <public-key> <ciphertext> <shared-secret>\n"
	        "  %s kem-decaps <secret-key> <ciphertext> <shared-secret>\n",
	        program, program, program, program, program, program);
}

static int write_bytes(const char *path, const uint8_t *bytes, size_t length) {
	FILE *file = fopen(path, "wb");
	if (file == NULL) {
		fprintf(stderr, "Could not open %s for writing: %s\n", path, strerror(errno));
		return EXIT_FAILURE;
	}
	const size_t written = fwrite(bytes, 1, length, file);
	const int close_result = fclose(file);
	if (written != length || close_result != 0) {
		fprintf(stderr, "Could not write %s completely.\n", path);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static uint8_t *read_bytes(const char *path, size_t expected_length) {
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	uint8_t *bytes = OQS_MEM_malloc(expected_length == 0 ? 1 : expected_length);
	if (bytes == NULL) {
		fclose(file);
		fprintf(stderr, "Could not allocate input buffer.\n");
		return NULL;
	}
	const size_t read = fread(bytes, 1, expected_length, file);
	const int trailing = fgetc(file);
	const int close_result = fclose(file);
	if (read != expected_length || trailing != EOF || close_result != 0) {
		fprintf(stderr, "%s does not contain exactly %zu bytes.\n", path, expected_length);
		OQS_MEM_insecure_free(bytes);
		return NULL;
	}
	return bytes;
}

static uint8_t *read_message(const char *path, size_t *length) {
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return NULL;
	}
	const long size = ftell(file);
	if (size < 0 || size > 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		fprintf(stderr, "Message must be between 0 and 1 MiB.\n");
		return NULL;
	}
	*length = (size_t)size;
	uint8_t *bytes = OQS_MEM_malloc(*length == 0 ? 1 : *length);
	if (bytes == NULL) {
		fclose(file);
		return NULL;
	}
	if (fread(bytes, 1, *length, file) != *length || fclose(file) != 0) {
		OQS_MEM_insecure_free(bytes);
		return NULL;
	}
	return bytes;
}

static int sig_keygen(const char *public_path, const char *secret_path) {
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL) {
		return EXIT_FAILURE;
	}
	uint8_t *public_key = OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key = OQS_MEM_malloc(sig->length_secret_key);
	int result = EXIT_FAILURE;
	if (public_key != NULL && secret_key != NULL &&
	    OQS_SIG_keypair(sig, public_key, secret_key) == OQS_SUCCESS &&
	    write_bytes(public_path, public_key, sig->length_public_key) == EXIT_SUCCESS &&
	    write_bytes(secret_path, secret_key, sig->length_secret_key) == EXIT_SUCCESS) {
		result = EXIT_SUCCESS;
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	OQS_SIG_free(sig);
	return result;
}

static int sig_sign(const char *secret_path, const char *message_path, const char *signature_path) {
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL) {
		return EXIT_FAILURE;
	}
	uint8_t *secret_key = read_bytes(secret_path, sig->length_secret_key);
	size_t message_length = 0;
	uint8_t *message = read_message(message_path, &message_length);
	uint8_t *signature = OQS_MEM_malloc(sig->length_signature);
	size_t signature_length = 0;
	int result = EXIT_FAILURE;
	if (secret_key != NULL && message != NULL && signature != NULL &&
	    OQS_SIG_sign(sig, signature, &signature_length, message, message_length, secret_key) == OQS_SUCCESS &&
	    signature_length <= sig->length_signature &&
	    write_bytes(signature_path, signature, signature_length) == EXIT_SUCCESS) {
		result = EXIT_SUCCESS;
	}
	OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
	return result;
}

static int sig_verify(const char *public_path, const char *message_path, const char *signature_path) {
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL) {
		return EXIT_FAILURE;
	}
	uint8_t *public_key = read_bytes(public_path, sig->length_public_key);
	size_t message_length = 0;
	uint8_t *message = read_message(message_path, &message_length);
	uint8_t *signature = read_bytes(signature_path, sig->length_signature);
	const int result = public_key != NULL && message != NULL && signature != NULL &&
	                           OQS_SIG_verify(sig, message, message_length, signature,
	                                          sig->length_signature, public_key) == OQS_SUCCESS
	                       ? EXIT_SUCCESS
	                       : EXIT_FAILURE;
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
	return result;
}

static int kem_keygen(const char *public_path, const char *secret_path) {
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL) {
		return EXIT_FAILURE;
	}
	uint8_t *public_key = OQS_MEM_malloc(kem->length_public_key);
	uint8_t *secret_key = OQS_MEM_malloc(kem->length_secret_key);
	int result = EXIT_FAILURE;
	if (public_key != NULL && secret_key != NULL &&
	    OQS_KEM_keypair(kem, public_key, secret_key) == OQS_SUCCESS &&
	    write_bytes(public_path, public_key, kem->length_public_key) == EXIT_SUCCESS &&
	    write_bytes(secret_path, secret_key, kem->length_secret_key) == EXIT_SUCCESS) {
		result = EXIT_SUCCESS;
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key, kem->length_secret_key);
	OQS_KEM_free(kem);
	return result;
}

static int kem_encaps(const char *public_path, const char *ciphertext_path, const char *secret_path) {
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL) {
		return EXIT_FAILURE;
	}
	uint8_t *public_key = read_bytes(public_path, kem->length_public_key);
	uint8_t *ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
	uint8_t *shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
	int result = EXIT_FAILURE;
	if (public_key != NULL && ciphertext != NULL && shared_secret != NULL &&
	    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) == OQS_SUCCESS &&
	    write_bytes(ciphertext_path, ciphertext, kem->length_ciphertext) == EXIT_SUCCESS &&
	    write_bytes(secret_path, shared_secret, kem->length_shared_secret) == EXIT_SUCCESS) {
		result = EXIT_SUCCESS;
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
	OQS_KEM_free(kem);
	return result;
}

static int kem_decaps(const char *secret_key_path, const char *ciphertext_path, const char *secret_path) {
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	if (kem == NULL) {
		return EXIT_FAILURE;
	}
	uint8_t *secret_key = read_bytes(secret_key_path, kem->length_secret_key);
	uint8_t *ciphertext = read_bytes(ciphertext_path, kem->length_ciphertext);
	uint8_t *shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
	int result = EXIT_FAILURE;
	if (secret_key != NULL && ciphertext != NULL && shared_secret != NULL &&
	    OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key) == OQS_SUCCESS &&
	    write_bytes(secret_path, shared_secret, kem->length_shared_secret) == EXIT_SUCCESS) {
		result = EXIT_SUCCESS;
	}
	OQS_MEM_secure_free(secret_key, kem->length_secret_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
	OQS_KEM_free(kem);
	return result;
}

int main(int argc, char **argv) {
	const int is_keygen = argc >= 2 &&
	                      (strcmp(argv[1], "sig-keygen") == 0 || strcmp(argv[1], "kem-keygen") == 0);
	if ((is_keygen && argc != 4) || (!is_keygen && argc != 5)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	OQS_init();
	int result = EXIT_FAILURE;
	if (strcmp(argv[1], "sig-keygen") == 0) {
		result = sig_keygen(argv[2], argv[3]);
	} else if (strcmp(argv[1], "sig-sign") == 0) {
		result = sig_sign(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "sig-verify") == 0) {
		result = sig_verify(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "kem-keygen") == 0) {
		result = kem_keygen(argv[2], argv[3]);
	} else if (strcmp(argv[1], "kem-encaps") == 0) {
		result = kem_encaps(argv[2], argv[3], argv[4]);
	} else if (strcmp(argv[1], "kem-decaps") == 0) {
		result = kem_decaps(argv[2], argv[3], argv[4]);
	} else {
		usage(argv[0]);
	}
	OQS_destroy();
	return result;
}
