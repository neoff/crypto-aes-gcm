package aesgcm

import (
	"encoding/base64"
	"testing"
)

func TestNewCipher(t *testing.T) {
	// Valid 32-byte key
	key := make([]byte, 32)
	cipher, err := NewCipher(key, 1)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	if cipher == nil {
		t.Fatal("Expected cipher, got nil")
	}

	// Invalid key length
	shortKey := make([]byte, 16)
	_, err = NewCipher(shortKey, 1)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey, got %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := NewCipher(key, 1)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	plaintext := "Hello, World! 🔒"

	// Encrypt
	ciphertext, err := cipher.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if ciphertext == "" {
		t.Fatal("Expected non-empty ciphertext")
	}

	// Decrypt
	decrypted, err := cipher.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected %q, got %q", plaintext, decrypted)
	}
}

func TestPackUnpack(t *testing.T) {
	ct := []byte("ciphertext")
	iv := make([]byte, IVBytes)
	tag := make([]byte, GCMTagBytes)
	keyVersion := 42

	// Create blob
	blob := NewAeadBlob(ct, iv, tag, keyVersion)

	// Pack
	packed := Pack(blob)
	if packed == "" {
		t.Fatal("Expected non-empty packed string")
	}

	// Verify URL-safe base64 (no padding)
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(packed)
	if err != nil {
		t.Fatalf("Pack should produce valid URL-safe base64: %v", err)
	}

	// Check magic bytes
	if decoded[0] != 'A' || decoded[1] != 'G' {
		t.Errorf("Expected magic bytes 'AG', got %c%c", decoded[0], decoded[1])
	}

	// Unpack
	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	// Verify fields
	if unpacked.KeyVersion() != keyVersion {
		t.Errorf("Expected key version %d, got %d", keyVersion, unpacked.KeyVersion())
	}

	if string(unpacked.Ciphertext()) != string(ct) {
		t.Errorf("Expected ciphertext %q, got %q", ct, unpacked.Ciphertext())
	}
}

func TestUnpackErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "invalid base64",
			input:   "not-base64!!!",
			wantErr: ErrInvalidFormat,
		},
		{
			name:    "too short",
			input:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte{1, 2}),
			wantErr: ErrInvalidFormat,
		},
		{
			name:    "bad magic",
			input:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte{0, 0, 1, 0, 0, 12, 16}),
			wantErr: ErrBadMagic,
		},
		{
			name:    "unsupported version",
			input:   base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte{'A', 'G', 99, 0, 0, 12, 16}),
			wantErr: ErrUnsupportedVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unpack(tt.input)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			// Check if error chain contains expected error
			if tt.wantErr != nil && !containsError(err, tt.wantErr) {
				t.Errorf("Expected error containing %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestKeyVersionMismatch(t *testing.T) {
	key := make([]byte, 32)
	cipher1, _ := NewCipher(key, 1)
	cipher2, _ := NewCipher(key, 2)

	// Encrypt with version 1
	ciphertext, err := cipher1.EncryptString("test")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with version 2
	_, err = cipher2.DecryptString(ciphertext)
	if err == nil {
		t.Fatal("Expected error for key version mismatch")
	}
	if !containsError(err, ErrKeyVersionMismatch) {
		t.Errorf("Expected ErrKeyVersionMismatch, got %v", err)
	}
}

func TestDefensiveCopying(t *testing.T) {
	ct := []byte("ciphertext")
	iv := make([]byte, IVBytes)
	tag := make([]byte, GCMTagBytes)

	blob := NewAeadBlob(ct, iv, tag, 1)

	// Modify original slices
	ct[0] = 'X'
	iv[0] = 'X'
	tag[0] = 'X'

	// Verify blob data is unchanged
	if blob.Ciphertext()[0] == 'X' {
		t.Error("Ciphertext was not defensively copied")
	}
	if blob.IV()[0] == 'X' {
		t.Error("IV was not defensively copied")
	}
	if blob.Tag()[0] == 'X' {
		t.Error("Tag was not defensively copied")
	}
}

func TestRoundTripWithBinaryData(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewCipher(key, 1)

	// Test with binary data (null bytes, high bytes, etc.)
	plaintext := []byte{0, 1, 2, 255, 254, 253, 0x00, 0xFF}

	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Length mismatch: expected %d, got %d", len(plaintext), len(decrypted))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Byte %d: expected %d, got %d", i, plaintext[i], decrypted[i])
		}
	}
}

// Helper function to check if error chain contains target error
func containsError(err, target error) bool {
	if err == nil {
		return false
	}
	if err == target {
		return true
	}
	// Simple string contains check for wrapped errors
	return err.Error() != "" && target.Error() != "" &&
		len(err.Error()) >= len(target.Error()) &&
		err.Error()[:len(target.Error())] == target.Error()
}
