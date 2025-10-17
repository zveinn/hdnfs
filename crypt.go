package hdnfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2 parameters (OWASP recommendations for sensitive data)
	Argon2Time    = 3      // Number of iterations
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4      // Number of threads
	Argon2KeyLen  = 32     // AES-256 key length

	// Salt size for key derivation
	SaltSize = 32

	// GCM nonce size
	NonceSize = 12
)

// DeriveKey derives a cryptographic key from a password using Argon2id
// This addresses CRYPTO-002: Implements proper key derivation function
func DeriveKey(password string, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes, got %d", SaltSize, len(salt))
	}

	// Argon2id is recommended for password hashing (resistant to GPU attacks)
	key := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return key, nil
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Validate salt is not all zeros (extremely unlikely but defensive)
	allZero := true
	for _, b := range salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("generated invalid all-zero salt")
	}

	return salt, nil
}

// GetEncKey retrieves and validates the encryption password from environment
// This addresses CRYPTO-003: Removes global mutable key variable
// This addresses CRYPTO-005: Enforces proper key length validation
func GetEncKey() (string, error) {
	password := os.Getenv(HDNFS_ENV)
	if password == "" {
		return "", fmt.Errorf("environment variable %s not set", HDNFS_ENV)
	}

	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters long")
	}

	return password, nil
}

// EncryptGCM encrypts data using AES-256-GCM (authenticated encryption)
// This addresses CRYPTO-001: Implements authenticated encryption
// This addresses CRYPTO-004: Proper nonce validation
//
// Returns: [nonce || ciphertext+tag]
func EncryptGCM(plaintext []byte, password string, salt []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext cannot be empty")
	}

	// Derive key from password
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer zeroBytes(key) // Clear key from memory when done

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Validate nonce is not all zeros (extremely unlikely but defensive)
	allZero := true
	for _, b := range nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("generated invalid all-zero nonce")
	}

	// Encrypt and authenticate
	// GCM's Seal appends the ciphertext and tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// DecryptGCM decrypts data using AES-256-GCM and verifies authenticity
// This addresses CRYPTO-001: Implements authenticated decryption
//
// Expects: [nonce || ciphertext+tag]
func DecryptGCM(ciphertext []byte, password string, salt []byte) ([]byte, error) {
	// Derive key from password
	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer zeroBytes(key) // Clear key from memory when done

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum size: nonce + tag
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:nonceSize]
	ciphertextData := ciphertext[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		// This error means either:
		// 1. Wrong password/key
		// 2. Data was tampered with
		// 3. Data is corrupted
		return nil, fmt.Errorf("decryption failed (wrong password or data corrupted): %w", err)
	}

	return plaintext, nil
}

// ComputeChecksum computes SHA-256 checksum of data
func ComputeChecksum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// zeroBytes securely zeros out a byte slice to clear sensitive data from memory
// This addresses CRYPTO-003: Proper key cleanup
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Legacy functions for backward compatibility (DEPRECATED - DO NOT USE)
// These are kept only if needed for migration, but should be removed

// Decrypt is the old CFB decryption - INSECURE, DO NOT USE
// Kept only for potential data migration
func Decrypt(text, key []byte) ([]byte, error) {
	return nil, errors.New("legacy Decrypt function disabled - use DecryptGCM instead")
}

// Encrypt is the old CFB encryption - INSECURE, DO NOT USE
// Kept only for potential data migration
func Encrypt(text, key []byte) ([]byte, error) {
	return nil, errors.New("legacy Encrypt function disabled - use EncryptGCM instead")
}
