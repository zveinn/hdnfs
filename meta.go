package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

func WriteMeta(file F, m *Meta) error {
	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	if m.Salt == nil || len(m.Salt) != SALT_SIZE {
		salt, err := GenerateSalt()
		if err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
		m.Salt = salt
	}

	m.Version = METADATA_VERSION

	metaJSON, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	encrypted, err := EncryptGCM(metaJSON, password, m.Salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	totalSize := HEADER_SIZE + len(encrypted) + CHECKSUM_SIZE
	if totalSize > META_FILE_SIZE {
		return fmt.Errorf("metadata too large: %d bytes (max %d)", totalSize, META_FILE_SIZE)
	}

	header := make([]byte, HEADER_SIZE)
	copy(header[0:MAGIC_SIZE], MAGIC_STRING)
	header[MAGIC_SIZE] = byte(METADATA_VERSION)

	copy(header[8:8+SALT_SIZE], m.Salt)
	binary.BigEndian.PutUint32(header[8+SALT_SIZE:HEADER_SIZE], uint32(len(encrypted)))

	checksumData := append(header, encrypted...)
	checksum := ComputeChecksum(checksumData)

	metaBlock := make([]byte, 0, META_FILE_SIZE)
	metaBlock = append(metaBlock, header...)
	metaBlock = append(metaBlock, encrypted...)
	metaBlock = append(metaBlock, checksum...)

	paddingSize := META_FILE_SIZE - len(metaBlock)
	if paddingSize > 0 {
		metaBlock = append(metaBlock, make([]byte, paddingSize)...)
	}

	if len(metaBlock) != META_FILE_SIZE {
		return fmt.Errorf("internal error: metadata block size mismatch: %d != %d", len(metaBlock), META_FILE_SIZE)
	}

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

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync metadata: %w", err)
	}

	return nil
}

func ReadMeta(file F) (*Meta, error) {
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

	magic := string(metaBlock[0:MAGIC_SIZE])
	if magic != MAGIC_STRING {
		return nil, errors.New("invalid filesystem: magic number mismatch (device not initialized or corrupted)")
	}

	version := int(metaBlock[MAGIC_SIZE])
	if version != METADATA_VERSION {
		return nil, fmt.Errorf("unsupported metadata version: %d (expected %d)", version, METADATA_VERSION)
	}

	salt := metaBlock[8 : 8+SALT_SIZE]

	encryptedLen := binary.BigEndian.Uint32(metaBlock[8+SALT_SIZE : HEADER_SIZE])

	encryptedStart := HEADER_SIZE
	encryptedEnd := encryptedStart + int(encryptedLen)
	if encryptedEnd > META_FILE_SIZE-CHECKSUM_SIZE {
		return nil, fmt.Errorf("encrypted data length exceeds metadata size: %d", encryptedLen)
	}

	encrypted := metaBlock[encryptedStart:encryptedEnd]

	checksumStart := encryptedEnd
	checksumEnd := checksumStart + CHECKSUM_SIZE
	if checksumEnd > META_FILE_SIZE {
		return nil, errors.New("checksum position exceeds metadata size")
	}
	storedChecksum := metaBlock[checksumStart:checksumEnd]

	checksumData := metaBlock[0:encryptedEnd]
	computedChecksum := ComputeChecksum(checksumData)

	if !bytes.Equal(storedChecksum, computedChecksum) {
		return nil, errors.New("metadata corrupted: checksum mismatch")
	}

	password, err := GetEncKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	metaJSON, err := DecryptGCM(encrypted, password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if meta.Version != METADATA_VERSION {
		return nil, fmt.Errorf("metadata version mismatch in JSON: %d (expected %d)", meta.Version, METADATA_VERSION)
	}

	return &meta, nil
}

func InitMeta(file F, mode string) error {
	if mode == "file" {

		currentPos, err := file.Seek(0, 1)
		if err != nil {
			return fmt.Errorf("failed to get current position: %w", err)
		}

		fileSize, err := file.Seek(0, 2)
		if err != nil {
			return fmt.Errorf("failed to seek to end: %w", err)
		}

		if _, err := file.Seek(currentPos, 0); err != nil {
			return fmt.Errorf("failed to restore position: %w", err)
		}

		if err := Overwrite(file, 0, uint64(fileSize)); err != nil {
			return fmt.Errorf("failed to overwrite device: %w", err)
		}
	}

	salt, err := GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	meta := &Meta{
		Version: METADATA_VERSION,
		Salt:    salt,
		Files:   [TOTAL_FILES]File{},
	}

	if err := WriteMeta(file, meta); err != nil {
		return fmt.Errorf("failed to write initial metadata: %w", err)
	}

	return nil
}
