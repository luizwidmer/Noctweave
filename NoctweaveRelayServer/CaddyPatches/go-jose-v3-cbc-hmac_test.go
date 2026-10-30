package josecipher

import (
	"crypto/aes"
	"strings"
	"testing"
)

func TestNoctweaveCBCHMACInvalidKeyLengths(t *testing.T) {
	for _, length := range []int{31, 47, 63} {
		cipher, err := NewCBCHMAC(make([]byte, length), aes.NewCipher)
		if cipher != nil || err == nil || !strings.Contains(err.Error(), "invalid key size") {
			t.Fatalf("key length %d: expected a construction error, got cipher=%v err=%v", length, cipher, err)
		}
	}
}

func TestNoctweaveCBCHMACEmptyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	aead, err := NewCBCHMAC(key, aes.NewCipher)
	if err != nil {
		t.Fatalf("valid key was rejected: %v", err)
	}
	ctx := aead.(*cbcAEAD)
	nonce := make([]byte, 16)
	aad := []byte("aad")
	tag := ctx.computeAuthTag(aad, nonce, nil)
	if _, err := aead.Open(nil, nonce, tag, aad); err == nil || !strings.Contains(err.Error(), "padding") {
		t.Fatalf("authenticated empty ciphertext was accepted or rejected for the wrong reason: %v", err)
	}
	if _, err := unpadBuffer(nil, 16); err == nil || !strings.Contains(err.Error(), "padding") {
		t.Fatalf("empty padding was accepted or rejected for the wrong reason: %v", err)
	}
}
