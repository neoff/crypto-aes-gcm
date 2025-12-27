# crypto-aes-gcm

Go implementation of AES-256-GCM.

## Features

- ✅ **AES-256-GCM** authenticated encryption
- ✅ **Key versioning** support for key rotation
- ✅ **Format versioning** for backward/forward compatibility
- ✅ **URL-safe Base64** encoding
- ✅ **Zero dependencies** - pure Go stdlib

## Binary Format

```
[MAGIC:AG][VERSION:1][KEY_VER:2bytes][IV_LEN:1byte][TAG_LEN:1byte][IV:12bytes][TAG:16bytes][CIPHERTEXT]
```

## Installation

```bash
go get github.com/neoff/crypto-aes-gcm
```

## Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/neoff/crypto-aes-gcm/aesgcm"
)

func main() {
    // Create 32-byte key (in production: use secure random key)
    key := make([]byte, 32)
    for i := range key {
        key[i] = byte(i)
    }
    
    // Create cipher with key version 1
    cipher, err := aesgcm.NewCipher(key, 1)
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt string
    ciphertext, err := cipher.EncryptString("Hello, World!")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Encrypted:", ciphertext)
    
    // Decrypt string
    plaintext, err := cipher.DecryptString(ciphertext)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Decrypted:", plaintext)
}
```

### Key Versioning

```go
// Create ciphers with different key versions
cipher1, _ := aesgcm.NewCipher(key, 1)
cipher2, _ := aesgcm.NewCipher(key, 2)

// Encrypt with version 1
encrypted, _ := cipher1.EncryptString("data")

// Can only decrypt with matching version
plaintext, _ := cipher1.DecryptString(encrypted)  // ✅ OK
_, err := cipher2.DecryptString(encrypted)        // ❌ ErrKeyVersionMismatch
```

## Compatibility

This implementation:
- Same URL-safe Base64 encoding
- Same magic bytes validation
- Same key versioning support

## License

MIT
