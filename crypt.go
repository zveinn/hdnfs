package main

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

	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32

	SaltSize = 32

	NonceSize = 12
)

func DeriveKey(password string, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes, got %d", SaltSize, len(salt))
	}

	key := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return key, nil
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

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

func EncryptGCM(plaintext []byte, password string, salt []byte) ([]byte, error) {

	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func DecryptGCM(ciphertext []byte, password string, salt []byte) ([]byte, error) {

	key, err := DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	nonce := ciphertext[:nonceSize]
	ciphertextData := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {

		return nil, fmt.Errorf("decryption failed (wrong password or data corrupted): %w", err)
	}

	return plaintext, nil
}

func ComputeChecksum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func Decrypt(text, key []byte) ([]byte, error) {
	return nil, errors.New("legacy Decrypt function disabled - use DecryptGCM instead")
}

func Encrypt(text, key []byte) ([]byte, error) {
	return nil, errors.New("legacy Encrypt function disabled - use EncryptGCM instead")
}
