package hdnfs

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"os"
	"testing"
)

func TestGetEncKey(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		expectPanic bool
	}{
		{
			name:        "Valid 32 byte key",
			envValue:    "12345678901234567890123456789012",
			expectPanic: false,
		},
		{
			name:        "Valid 64 byte key",
			envValue:    "1234567890123456789012345678901212345678901234567890123456789012",
			expectPanic: false,
		},
		{
			name:        "Missing key",
			envValue:    "",
			expectPanic: true,
		},
		{
			name:        "Key too short",
			envValue:    "short",
			expectPanic: true,
		},
		{
			name:        "Key exactly 31 bytes",
			envValue:    "1234567890123456789012345678901",
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cached key
			KEY = []byte{}

			if tt.envValue == "" {
				os.Unsetenv(HDNFS_ENV)
			} else {
				os.Setenv(HDNFS_ENV, tt.envValue)
			}
			defer os.Unsetenv(HDNFS_ENV)

			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic but didn't get one")
					}
				}()
				GetEncKey()
			} else {
				key := GetEncKey()
				if len(key) != len(tt.envValue) {
					t.Errorf("Expected key length %d, got %d", len(tt.envValue), len(key))
				}
				if string(key) != tt.envValue {
					t.Errorf("Key mismatch")
				}

				// Test key caching
				KEY_cached := GetEncKey()
				if !bytes.Equal(key, KEY_cached) {
					t.Errorf("Cached key doesn't match")
				}
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty data",
			data: []byte{},
		},
		{
			name: "Small data",
			data: []byte("Hello, World!"),
		},
		{
			name: "Medium data",
			data: GenerateRandomBytes(1024),
		},
		{
			name: "Large data",
			data: GenerateRandomBytes(MAX_FILE_SIZE - aes.BlockSize - 100), // Leave room for IV
		},
		{
			name: "Binary data with nulls",
			data: []byte{0x00, 0x01, 0x02, 0x00, 0xFF, 0xFE, 0x00},
		},
		{
			name: "Unicode text",
			data: []byte("Hello 世界 🌍"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GetEncKey()

			// Encrypt
			encrypted := Encrypt(tt.data, key)

			// Verify IV is present (first 16 bytes)
			if len(encrypted) < aes.BlockSize {
				t.Fatalf("Encrypted data too short: %d bytes", len(encrypted))
			}

			// Verify encrypted data is longer than original (due to IV)
			if len(encrypted) != len(tt.data)+aes.BlockSize {
				t.Errorf("Expected encrypted length %d, got %d", len(tt.data)+aes.BlockSize, len(encrypted))
			}

			// Decrypt
			decrypted := Decrypt(encrypted, key)

			// Verify decrypted matches original
			if !bytes.Equal(decrypted, tt.data) {
				t.Errorf("Decrypted data doesn't match original")
				t.Errorf("Original length: %d, Decrypted length: %d", len(tt.data), len(decrypted))
				if len(tt.data) < 100 {
					t.Errorf("Original: %v", tt.data)
					t.Errorf("Decrypted: %v", decrypted)
				}
			}
		})
	}
}

func TestEncryptionRandomness(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	data := []byte("Same data encrypted twice")
	key := GetEncKey()

	// Encrypt same data twice
	encrypted1 := Encrypt(data, key)
	encrypted2 := Encrypt(data, key)

	// IVs should be different (first 16 bytes)
	if bytes.Equal(encrypted1[:aes.BlockSize], encrypted2[:aes.BlockSize]) {
		t.Error("IVs should be random and different for each encryption")
	}

	// Full ciphertexts should be different
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encrypting same data twice should produce different ciphertexts")
	}

	// Both should decrypt to same plaintext
	decrypted1 := Decrypt(encrypted1, key)
	decrypted2 := Decrypt(encrypted2, key)

	if !bytes.Equal(decrypted1, data) {
		t.Error("First decryption failed")
	}
	if !bytes.Equal(decrypted2, data) {
		t.Error("Second decryption failed")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	data := []byte("Secret message")
	correctKey := GetEncKey()
	wrongKey := []byte("WRONGKEY901234567890123456789012")

	encrypted := Encrypt(data, correctKey)

	// Decrypt with wrong key
	decrypted := Decrypt(encrypted, wrongKey)

	// Should not match original
	if bytes.Equal(decrypted, data) {
		t.Error("Decryption with wrong key should not produce correct plaintext")
	}
}

func TestDecryptTruncatedData(t *testing.T) {
	t.Skip("Skipping test that causes os.Exit - truncated data triggers PrintError which calls os.Exit")
	// This test verifies that short ciphertext (< AES block size) is handled
	// Current implementation calls PrintError -> os.Exit(1)
	// In production, should return error instead
}

func TestEncryptionPreservesLength(t *testing.T) {
	SetupTestKey(t)
	defer CleanupTestKey(t)

	key := GetEncKey()

	for size := 0; size < 1000; size += 100 {
		data := GenerateRandomBytes(size)
		encrypted := Encrypt(data, key)

		expectedLen := size + aes.BlockSize
		if len(encrypted) != expectedLen {
			t.Errorf("Size %d: expected encrypted length %d, got %d", size, expectedLen, len(encrypted))
		}
	}
}

func TestEncryptWithDifferentKeySizes(t *testing.T) {
	// AES supports 16, 24, or 32 byte keys
	tests := []struct {
		name      string
		keySize   int
		shouldErr bool
	}{
		{
			name:      "16 byte key (AES-128)",
			keySize:   16,
			shouldErr: false,
		},
		{
			name:      "24 byte key (AES-192)",
			keySize:   24,
			shouldErr: false,
		},
		{
			name:      "32 byte key (AES-256)",
			keySize:   32,
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := GenerateRandomBytes(tt.keySize)
			data := []byte("Test data")

			// In the current implementation, invalid key sizes cause panic via PrintError + os.Exit
			// We can't easily test this without refactoring error handling
			encrypted := Encrypt(data, key)
			decrypted := Decrypt(encrypted, key)

			if !bytes.Equal(decrypted, data) {
				t.Error("Encryption/decryption round trip failed")
			}
		})
	}
}

func TestEncryptLargeData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large data test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	key := GetEncKey()

	// Test with progressively larger data
	sizes := []int{
		1024,           // 1KB
		10 * 1024,      // 10KB
		100 * 1024,     // 100KB
		1024 * 1024,    // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			data := GenerateRandomBytes(size)
			encrypted := Encrypt(data, key)
			decrypted := Decrypt(encrypted, key)

			if !bytes.Equal(decrypted, data) {
				t.Errorf("Failed to encrypt/decrypt %d bytes", size)
			}
		})
	}
}

func TestEncryptEmptyKey(t *testing.T) {
	t.Skip("Skipping test that causes os.Exit - empty key triggers PrintError which calls os.Exit")
	// In a production system, Encrypt should return an error instead of calling os.Exit
	// This test documents that the current implementation has this limitation
}

func BenchmarkEncrypt(b *testing.B) {
	SetupTestKey(&testing.T{})
	key := GetEncKey()
	data := GenerateRandomBytes(1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(data, key)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	SetupTestKey(&testing.T{})
	key := GetEncKey()
	data := GenerateRandomBytes(1024)
	encrypted := Encrypt(data, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(encrypted, key)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	SetupTestKey(&testing.T{})
	key := GetEncKey()
	data := GenerateRandomBytes(1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted := Encrypt(data, key)
		Decrypt(encrypted, key)
	}
}
