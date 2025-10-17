package hdnfs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// WriteMeta writes metadata to the device with full integrity protection
// Format: [Magic 5][Version 1][Reserved 2][Salt 32][Length 4][Encrypted Data][Checksum 32][Padding]
func WriteMeta(file F, m *Meta) error {
	// Get password
	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Ensure salt exists
	if m.Salt == nil || len(m.Salt) != SALT_SIZE {
		salt, err := GenerateSalt()
		if err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
		m.Salt = salt
	}

	// Set version
	m.Version = METADATA_VERSION

	// Serialize metadata to JSON
	metaJSON, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Encrypt metadata using GCM
	encrypted, err := EncryptGCM(metaJSON, password, m.Salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Check if encrypted metadata fits in allocated space
	totalSize := HEADER_SIZE + len(encrypted) + CHECKSUM_SIZE
	if totalSize > META_FILE_SIZE {
		return fmt.Errorf("metadata too large: %d bytes (max %d)", totalSize, META_FILE_SIZE)
	}

	// Build header
	header := make([]byte, HEADER_SIZE)
	copy(header[0:MAGIC_SIZE], MAGIC_STRING)
	header[MAGIC_SIZE] = byte(METADATA_VERSION)
	// Reserved bytes at [6:8] are left as zeros
	copy(header[8:8+SALT_SIZE], m.Salt)
	binary.BigEndian.PutUint32(header[8+SALT_SIZE:HEADER_SIZE], uint32(len(encrypted)))

	// Compute checksum over header + encrypted data
	checksumData := append(header, encrypted...)
	checksum := ComputeChecksum(checksumData)

	// Build final metadata block: Header + Encrypted + Checksum + Padding
	metaBlock := make([]byte, 0, META_FILE_SIZE)
	metaBlock = append(metaBlock, header...)
	metaBlock = append(metaBlock, encrypted...)
	metaBlock = append(metaBlock, checksum...)

	// Add padding to reach META_FILE_SIZE
	paddingSize := META_FILE_SIZE - len(metaBlock)
	if paddingSize > 0 {
		metaBlock = append(metaBlock, make([]byte, paddingSize)...)
	}

	// Verify final size
	if len(metaBlock) != META_FILE_SIZE {
		return fmt.Errorf("internal error: metadata block size mismatch: %d != %d", len(metaBlock), META_FILE_SIZE)
	}

	// Write to file
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to metadata position: %w", err)
	}

	n, err := file.Write(metaBlock)
	if err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	if n != META_FILE_SIZE {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, META_FILE_SIZE)
	}

	// Sync to ensure data is persisted
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync metadata: %w", err)
	}

	return nil
}

// ReadMeta reads and validates metadata from the device
func ReadMeta(file F) (*Meta, error) {
	// Read entire metadata block
	metaBlock := make([]byte, META_FILE_SIZE)

	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek to metadata: %w", err)
	}

	n, err := file.Read(metaBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	if n != META_FILE_SIZE {
		return nil, fmt.Errorf("short read: read %d bytes, expected %d", n, META_FILE_SIZE)
	}

	// Check magic number
	magic := string(metaBlock[0:MAGIC_SIZE])
	if magic != MAGIC_STRING {
		return nil, errors.New("invalid filesystem: magic number mismatch (device not initialized or corrupted)")
	}

	// Check version
	version := int(metaBlock[MAGIC_SIZE])
	if version != METADATA_VERSION {
		return nil, fmt.Errorf("unsupported metadata version: %d (expected %d)", version, METADATA_VERSION)
	}

	// Extract salt
	salt := metaBlock[8 : 8+SALT_SIZE]

	// Extract encrypted data length
	encryptedLen := binary.BigEndian.Uint32(metaBlock[8+SALT_SIZE : HEADER_SIZE])
	if encryptedLen > math.MaxUint32 {
		return nil, fmt.Errorf("invalid encrypted data length: %d", encryptedLen)
	}

	// Extract encrypted data
	encryptedStart := HEADER_SIZE
	encryptedEnd := encryptedStart + int(encryptedLen)
	if encryptedEnd > META_FILE_SIZE-CHECKSUM_SIZE {
		return nil, fmt.Errorf("encrypted data length exceeds metadata size: %d", encryptedLen)
	}

	encrypted := metaBlock[encryptedStart:encryptedEnd]

	// Extract stored checksum
	checksumStart := encryptedEnd
	checksumEnd := checksumStart + CHECKSUM_SIZE
	if checksumEnd > META_FILE_SIZE {
		return nil, errors.New("checksum position exceeds metadata size")
	}
	storedChecksum := metaBlock[checksumStart:checksumEnd]

	// Compute checksum over header + encrypted data
	checksumData := metaBlock[0:encryptedEnd]
	computedChecksum := ComputeChecksum(checksumData)

	// Verify checksum
	if !bytes.Equal(storedChecksum, computedChecksum) {
		return nil, errors.New("metadata corrupted: checksum mismatch")
	}

	// Get password
	password, err := GetEncKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Decrypt metadata
	metaJSON, err := DecryptGCM(encrypted, password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	// Deserialize metadata
	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Validate metadata
	if meta.Version != METADATA_VERSION {
		return nil, fmt.Errorf("metadata version mismatch in JSON: %d (expected %d)", meta.Version, METADATA_VERSION)
	}

	return &meta, nil
}

// InitMeta initializes a new filesystem with metadata
func InitMeta(file F, mode string) error {
	// Optionally overwrite the entire file/device with zeros
	if mode == "file" {
		totalFileSize := META_FILE_SIZE + (TOTAL_FILES * MAX_FILE_SIZE)
		if err := Overwrite(file, 0, uint64(totalFileSize)); err != nil {
			return fmt.Errorf("failed to overwrite device: %w", err)
		}
	}

	// Generate salt for this filesystem
	salt, err := GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create empty metadata
	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
		Files:   [TOTAL_FILES]File{}, // All files empty
	}

	// Write metadata
	if err := WriteMeta(file, meta); err != nil {
		return fmt.Errorf("failed to write initial metadata: %w", err)
	}

	return nil
}
