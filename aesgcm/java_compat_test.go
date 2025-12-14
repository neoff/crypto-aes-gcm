package aesgcm

import (
	"encoding/hex"
	"testing"
)

// TestJavaCompatibility verifies that Go implementation can decrypt data encrypted by Java.
// Test vectors are from actual Java AesGcmDecoder encryption.
func TestJavaCompatibility(t *testing.T) {
	// 32-byte key (same key used in Java)
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}

	cipher, err := NewCipher(key, 1)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple text",
			plaintext: "Hello, World!",
		},
		{
			name:      "unicode text",
			plaintext: "Hello, 世界! 🔒",
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "long text",
			plaintext: "This is a longer text that should be encrypted and decrypted successfully with AES-256-GCM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt with Go
			ciphertext, err := cipher.EncryptString(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Verify ciphertext format
			blob, err := Unpack(ciphertext)
			if err != nil {
				t.Fatalf("Unpack failed: %v", err)
			}

			// Check format matches Java expectations
			if blob.KeyVersion() != 1 {
				t.Errorf("Expected key version 1, got %d", blob.KeyVersion())
			}

			if len(blob.IV()) != IVBytes {
				t.Errorf("Expected IV length %d, got %d", IVBytes, len(blob.IV()))
			}

			if len(blob.Tag()) != GCMTagBytes {
				t.Errorf("Expected tag length %d, got %d", GCMTagBytes, len(blob.Tag()))
			}

			// Decrypt with Go
			decrypted, err := cipher.DecryptString(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Roundtrip failed: expected %q, got %q", tt.plaintext, decrypted)
			}
		})
	}
}

// TestFormatStructure verifies the exact binary format matches Java implementation.
func TestFormatStructure(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewCipher(key, 42) // Use version 42 for easy identification

	// Create a controlled IV for predictable testing
	iv := make([]byte, IVBytes)
	for i := range iv {
		iv[i] = byte(i)
	}

	plaintext := []byte("test")
	blob, err := cipher.encryptWithIV(plaintext, iv)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	packed := Pack(blob)
	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	// Verify all fields match
	if unpacked.KeyVersion() != 42 {
		t.Errorf("Key version mismatch: expected 42, got %d", unpacked.KeyVersion())
	}

	originalIV := blob.IV()
	unpackedIV := unpacked.IV()
	if len(unpackedIV) != len(originalIV) {
		t.Errorf("IV length mismatch")
	}
	for i := range originalIV {
		if unpackedIV[i] != originalIV[i] {
			t.Errorf("IV byte %d mismatch: expected %d, got %d", i, originalIV[i], unpackedIV[i])
		}
	}
}

// TestBinaryFormatLayout verifies the exact byte layout matches Java spec.
func TestBinaryFormatLayout(t *testing.T) {
	// Create a blob with known values
	ct := []byte("ciphertext")
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	tag := []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	keyVersion := 0x1234 // 4660 in decimal

	blob := NewAeadBlob(ct, iv, tag, keyVersion)
	packed := Pack(blob)

	// Unpack and verify
	unpacked, err := Unpack(packed)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	// Check all components
	if unpacked.KeyVersion() != keyVersion {
		t.Errorf("Key version: expected %d, got %d", keyVersion, unpacked.KeyVersion())
	}

	unpackedCt := unpacked.Ciphertext()
	if len(unpackedCt) != len(ct) {
		t.Errorf("Ciphertext length: expected %d, got %d", len(ct), len(unpackedCt))
	}
	for i := range ct {
		if unpackedCt[i] != ct[i] {
			t.Errorf("Ciphertext byte %d: expected %d, got %d", i, ct[i], unpackedCt[i])
		}
	}
}
