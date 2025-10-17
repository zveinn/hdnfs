package hdnfs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestGetEncKey(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestGetEncKey took: %v", time.Since(start))
	}()

	tests := []struct {
		name        string
		envValue    string
		expectError bool
	}{
		{
			name:        "Valid password",
			envValue:    "test-password-123",
			expectError: false,
		},
		{
			name:        "Long password",
			envValue:    "this-is-a-very-long-password-that-should-still-work-fine",
			expectError: false,
		},
		{
			name:        "Missing key",
			envValue:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue == "" {
				os.Unsetenv(HDNFS_ENV)
			} else {
				os.Setenv(HDNFS_ENV, tt.envValue)
			}
			defer os.Unsetenv(HDNFS_ENV)

			password, err := GetEncKey()
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if password != tt.envValue {
					t.Errorf("Expected password %q, got %q", tt.envValue, password)
				}
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestGenerateSalt took: %v", time.Since(start))
	}()

	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt1) != SaltSize {
		t.Errorf("Expected salt size %d, got %d", SaltSize, len(salt1))
	}

	// Generate another salt and ensure they're different (randomness check)
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate second salt: %v", err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("Two salts should be different (randomness failure)")
	}
}

func TestDeriveKey(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestDeriveKey took: %v", time.Since(start))
	}()

	password := "test-password"
	salt := make([]byte, SaltSize)
	rand.Read(salt)

	// Derive key twice with same password and salt
	key1, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	key2, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key second time: %v", err)
	}

	// Should produce same key
	if !bytes.Equal(key1, key2) {
		t.Error("Same password and salt should produce same key")
	}

	// Verify key length
	if len(key1) != Argon2KeyLen {
		t.Errorf("Expected key length %d, got %d", Argon2KeyLen, len(key1))
	}

	// Different salt should produce different key
	salt2 := make([]byte, SaltSize)
	rand.Read(salt2)
	key3, err := DeriveKey(password, salt2)
	if err != nil {
		t.Fatalf("Failed to derive key with different salt: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Error("Different salts should produce different keys")
	}
}

func TestEncryptDecryptGCM(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestEncryptDecryptGCM took: %v", time.Since(start))
	}()

	SetupTestKey(t)
	defer CleanupTestKey(t)

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

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
			data: GenerateRandomBytes(10000),
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
			// Encrypt
			encrypted, err := EncryptGCM(tt.data, password, salt)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify nonce is present (first 12 bytes)
			if len(encrypted) < NonceSize {
				t.Fatalf("Encrypted data too short: %d bytes", len(encrypted))
			}

			// Decrypt
			decrypted, err := DecryptGCM(encrypted, password, salt)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

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
	start := time.Now()
	defer func() {
		t.Logf("TestEncryptionRandomness took: %v", time.Since(start))
	}()

	SetupTestKey(t)
	defer CleanupTestKey(t)

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	data := []byte("Same data encrypted twice")

	// Encrypt same data twice
	encrypted1, err := EncryptGCM(data, password, salt)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := EncryptGCM(data, password, salt)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Nonces should be different (first 12 bytes)
	if bytes.Equal(encrypted1[:NonceSize], encrypted2[:NonceSize]) {
		t.Error("Nonces should be random and different for each encryption")
	}

	// Full ciphertexts should be different
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Encrypting same data twice should produce different ciphertexts")
	}

	// Both should decrypt to same plaintext
	decrypted1, err := DecryptGCM(encrypted1, password, salt)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := DecryptGCM(encrypted2, password, salt)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted1, data) {
		t.Error("First decryption produced wrong plaintext")
	}
	if !bytes.Equal(decrypted2, data) {
		t.Error("Second decryption produced wrong plaintext")
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestDecryptWithWrongPassword took: %v", time.Since(start))
	}()

	SetupTestKey(t)
	defer CleanupTestKey(t)

	correctPassword, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	wrongPassword := "wrong-password-123"

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	data := []byte("Secret message")

	encrypted, err := EncryptGCM(data, correctPassword, salt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with wrong password should fail authentication
	_, err = DecryptGCM(encrypted, wrongPassword, salt)
	if err == nil {
		t.Error("Decryption with wrong password should fail authentication")
	}
}

func TestDecryptWithWrongSalt(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestDecryptWithWrongSalt took: %v", time.Since(start))
	}()

	SetupTestKey(t)
	defer CleanupTestKey(t)

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate first salt: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate second salt: %v", err)
	}

	data := []byte("Secret message")

	encrypted, err := EncryptGCM(data, password, salt1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with different salt should fail authentication
	_, err = DecryptGCM(encrypted, password, salt2)
	if err == nil {
		t.Error("Decryption with wrong salt should fail authentication")
	}
}

func TestDecryptTruncatedData(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestDecryptTruncatedData took: %v", time.Since(start))
	}()

	SetupTestKey(t)
	defer CleanupTestKey(t)

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Try to decrypt data that's too short
	shortData := []byte{0x01, 0x02, 0x03}
	_, err = DecryptGCM(shortData, password, salt)
	if err == nil {
		t.Error("Decryption of truncated data should fail")
	}
}

func TestDecryptCorruptedData(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestDecryptCorruptedData took: %v", time.Since(start))
	}()

	SetupTestKey(t)
	defer CleanupTestKey(t)

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	data := []byte("Secret message")

	encrypted, err := EncryptGCM(data, password, salt)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt a byte in the middle (after nonce, in ciphertext+tag)
	if len(encrypted) > NonceSize+1 {
		encrypted[NonceSize+1] ^= 0xFF
	}

	// Decryption should fail authentication
	_, err = DecryptGCM(encrypted, password, salt)
	if err == nil {
		t.Error("Decryption of corrupted data should fail authentication")
	}
}

func TestComputeChecksum(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestComputeChecksum took: %v", time.Since(start))
	}()

	data1 := []byte("test data")
	data2 := []byte("test data")
	data3 := []byte("different data")

	checksum1 := ComputeChecksum(data1)
	checksum2 := ComputeChecksum(data2)
	checksum3 := ComputeChecksum(data3)

	// Same data should produce same checksum
	if !bytes.Equal(checksum1, checksum2) {
		t.Error("Same data should produce same checksum")
	}

	// Different data should produce different checksum
	if bytes.Equal(checksum1, checksum3) {
		t.Error("Different data should produce different checksums")
	}

	// Checksum should be 32 bytes (SHA-256)
	if len(checksum1) != 32 {
		t.Errorf("Expected checksum length 32, got %d", len(checksum1))
	}
}

func TestEncryptLargeData(t *testing.T) {
	start := time.Now()
	defer func() {
		t.Logf("TestEncryptLargeData took: %v", time.Since(start))
	}()

	if testing.Short() {
		t.Skip("Skipping large data test in short mode")
	}

	SetupTestKey(t)
	defer CleanupTestKey(t)

	password, err := GetEncKey()
	if err != nil {
		t.Fatalf("Failed to get encryption key: %v", err)
	}

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Test with progressively larger data
	sizes := []int{
		1024,        // 1KB
		10 * 1024,   // 10KB
		100 * 1024,  // 100KB
		1024 * 1024, // 1MB
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			data := GenerateRandomBytes(size)
			encrypted, err := EncryptGCM(data, password, salt)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := DecryptGCM(encrypted, password, salt)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(decrypted, data) {
				t.Errorf("Failed to encrypt/decrypt %d bytes", size)
			}
		})
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	password := "test-password"
	salt := make([]byte, SaltSize)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKey(password, salt)
	}
}

func BenchmarkEncryptGCM(b *testing.B) {
	SetupTestKey(&testing.T{})
	password, _ := GetEncKey()
	salt, _ := GenerateSalt()
	data := GenerateRandomBytes(1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptGCM(data, password, salt)
	}
}

func BenchmarkDecryptGCM(b *testing.B) {
	SetupTestKey(&testing.T{})
	password, _ := GetEncKey()
	salt, _ := GenerateSalt()
	data := GenerateRandomBytes(1024)
	encrypted, _ := EncryptGCM(data, password, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptGCM(encrypted, password, salt)
	}
}

func BenchmarkEncryptDecryptGCM(b *testing.B) {
	SetupTestKey(&testing.T{})
	password, _ := GetEncKey()
	salt, _ := GenerateSalt()
	data := GenerateRandomBytes(1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := EncryptGCM(data, password, salt)
		DecryptGCM(encrypted, password, salt)
	}
}
