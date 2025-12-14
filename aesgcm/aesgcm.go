// Package aesgcm provides AES-256-GCM encryption compatible with Java AesGcmDecoder.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// GCMTagBytes is the size of the GCM authentication tag (16 bytes)
	GCMTagBytes = 16
	// IVBytes is the size of the initialization vector (12 bytes)
	IVBytes = 12
	// FormatVersion is the current format version
	FormatVersion byte = 1
)

var (
	// Magic bytes "AG" to identify the format
	magic = []byte{'A', 'G'}

	// ErrInvalidKey indicates the key size is not 32 bytes
	ErrInvalidKey = errors.New("invalid encryption key: must be 32 bytes for AES-256")
	// ErrInvalidFormat indicates the ciphertext format is invalid
	ErrInvalidFormat = errors.New("invalid ciphertext format")
	// ErrBadMagic indicates the magic bytes don't match
	ErrBadMagic = errors.New("bad magic bytes")
	// ErrUnsupportedVersion indicates the format version is not supported
	ErrUnsupportedVersion = errors.New("unsupported format version")
	// ErrCorruptedBlob indicates the blob is corrupted
	ErrCorruptedBlob = errors.New("corrupted blob")
	// ErrKeyVersionMismatch indicates the key version doesn't match expected
	ErrKeyVersionMismatch = errors.New("key version mismatch")
	// ErrEncryptionFailed indicates encryption failed
	ErrEncryptionFailed = errors.New("encryption failed")
	// ErrDecryptionFailed indicates decryption failed
	ErrDecryptionFailed = errors.New("decryption failed")
)

// AeadBlob represents an immutable AEAD blob containing ciphertext, IV, tag, and key version.
type AeadBlob struct {
	ct         []byte
	iv         []byte
	tag        []byte
	keyVersion int
}

// NewAeadBlob creates a new AeadBlob with defensive copying.
func NewAeadBlob(ct, iv, tag []byte, keyVersion int) *AeadBlob {
	blob := &AeadBlob{
		ct:         make([]byte, len(ct)),
		iv:         make([]byte, len(iv)),
		tag:        make([]byte, len(tag)),
		keyVersion: keyVersion,
	}
	copy(blob.ct, ct)
	copy(blob.iv, iv)
	copy(blob.tag, tag)
	return blob
}

// Ciphertext returns a copy of the ciphertext.
func (b *AeadBlob) Ciphertext() []byte {
	ct := make([]byte, len(b.ct))
	copy(ct, b.ct)
	return ct
}

// IV returns a copy of the initialization vector.
func (b *AeadBlob) IV() []byte {
	iv := make([]byte, len(b.iv))
	copy(iv, b.iv)
	return iv
}

// Tag returns a copy of the authentication tag.
func (b *AeadBlob) Tag() []byte {
	tag := make([]byte, len(b.tag))
	copy(tag, b.tag)
	return tag
}

// KeyVersion returns the key version.
func (b *AeadBlob) KeyVersion() int {
	return b.keyVersion
}

// Pack serializes the AEAD blob to URL-safe base64 string.
// Format: [MAGIC:AG][VERSION:1][KEY_VER:2bytes][IV_LEN][TAG_LEN][IV][TAG][CT]
func Pack(blob *AeadBlob) string {
	iv := blob.IV()
	tag := blob.Tag()
	ct := blob.Ciphertext()

	// Calculate total length: 2 (magic) + 1 (version) + 2 (key version) + 1 (iv len) + 1 (tag len) + iv + tag + ct
	length := 7 + len(iv) + len(tag) + len(ct)
	buf := make([]byte, length)

	// Write magic bytes
	copy(buf[0:2], magic)

	// Write format version
	buf[2] = FormatVersion

	// Write key version (big-endian uint16)
	binary.BigEndian.PutUint16(buf[3:5], uint16(blob.keyVersion))

	// Write lengths
	buf[5] = byte(len(iv))
	buf[6] = byte(len(tag))

	// Write IV, tag, and ciphertext
	offset := 7
	copy(buf[offset:], iv)
	offset += len(iv)
	copy(buf[offset:], tag)
	offset += len(tag)
	copy(buf[offset:], ct)

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(buf)
}

// Unpack deserializes a URL-safe base64 string to an AEAD blob.
func Unpack(packed string) (*AeadBlob, error) {
	raw, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(packed)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64: %v", ErrInvalidFormat, err)
	}

	if len(raw) < 7 {
		return nil, fmt.Errorf("%w: too short", ErrInvalidFormat)
	}

	// Check magic bytes
	if raw[0] != 'A' || raw[1] != 'G' {
		return nil, ErrBadMagic
	}

	// Check format version
	if raw[2] != FormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, raw[2])
	}

	// Read key version
	keyVersion := int(binary.BigEndian.Uint16(raw[3:5]))

	// Read lengths
	ivLen := int(raw[5])
	tagLen := int(raw[6])

	// Validate remaining data
	if len(raw) < 7+ivLen+tagLen {
		return nil, ErrCorruptedBlob
	}

	// Extract IV, tag, and ciphertext
	offset := 7
	iv := raw[offset : offset+ivLen]
	offset += ivLen
	tag := raw[offset : offset+tagLen]
	offset += tagLen
	ct := raw[offset:]

	return NewAeadBlob(ct, iv, tag, keyVersion), nil
}

// Cipher handles AES-GCM encryption/decryption with key versioning.
type Cipher struct {
	key        []byte
	keyVersion int
}

// NewCipher creates a new AES-GCM cipher with 256-bit key.
func NewCipher(key []byte, keyVersion int) (*Cipher, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return &Cipher{
		key:        keyCopy,
		keyVersion: keyVersion,
	}, nil
}

// Encrypt encrypts plaintext and returns a packed blob string.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	blob, err := c.EncryptToBlob(plaintext)
	if err != nil {
		return "", err
	}
	return Pack(blob), nil
}

// EncryptString encrypts a string and returns a packed blob string.
func (c *Cipher) EncryptString(plaintext string) (string, error) {
	return c.Encrypt([]byte(plaintext))
}

// EncryptToBlob encrypts plaintext and returns an AeadBlob.
func (c *Cipher) EncryptToBlob(plaintext []byte) (*AeadBlob, error) {
	// Generate random IV
	iv := make([]byte, IVBytes)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("%w: failed to generate IV: %v", ErrEncryptionFailed, err)
	}

	return c.encryptWithIV(plaintext, iv)
}

// encryptWithIV encrypts plaintext with a specific IV (for testing).
func (c *Cipher) encryptWithIV(plaintext, iv []byte) (*AeadBlob, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Seal appends tag to ciphertext: [ciphertext][tag]
	sealed := gcm.Seal(nil, iv, plaintext, nil)

	// Split ciphertext and tag
	ctLen := len(sealed) - GCMTagBytes
	ct := sealed[:ctLen]
	tag := sealed[ctLen:]

	return NewAeadBlob(ct, iv, tag, c.keyVersion), nil
}

// Decrypt decrypts a packed blob string and returns plaintext.
func (c *Cipher) Decrypt(packed string) ([]byte, error) {
	blob, err := Unpack(packed)
	if err != nil {
		return nil, err
	}
	return c.DecryptBlob(blob)
}

// DecryptString decrypts a packed blob string and returns plaintext as string.
func (c *Cipher) DecryptString(packed string) (string, error) {
	plaintext, err := c.Decrypt(packed)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// DecryptBlob decrypts an AeadBlob and returns plaintext.
func (c *Cipher) DecryptBlob(blob *AeadBlob) ([]byte, error) {
	// Check key version
	if blob.KeyVersion() != c.keyVersion {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrKeyVersionMismatch, c.keyVersion, blob.KeyVersion())
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Combine ciphertext and tag for GCM Open
	ct := blob.Ciphertext()
	tag := blob.Tag()
	combined := make([]byte, len(ct)+len(tag))
	copy(combined, ct)
	copy(combined[len(ct):], tag)

	plaintext, err := gcm.Open(nil, blob.IV(), combined, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}
