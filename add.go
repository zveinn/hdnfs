package hdnfs

import (
	"fmt"
	"os"
)

func Add(file F, path string, name string, index int) error {
	// Stat the input file
	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Validate filename length
	if len(name) > MAX_FILE_NAME_SIZE {
		return fmt.Errorf("filename too long: %d (max %d)", len(name), MAX_FILE_NAME_SIZE)
	}

	// Read metadata
	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Find available file slot
	nextFileIndex := 0
	foundIndex := false

	// Validate index if provided
	if index != OUT_OF_BOUNDS_INDEX {
		if index < 0 || index >= len(meta.Files) {
			return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, len(meta.Files)-1)
		}
		nextFileIndex = index
		foundIndex = true
	} else {
		// Find first available slot
		for i, v := range meta.Files {
			if v.Name == "" {
				nextFileIndex = i
				foundIndex = true
				break
			}
		}
	}

	if !foundIndex {
		return fmt.Errorf("no more file slots available (max %d files)", TOTAL_FILES)
	}

	// Use file name if not provided
	if name == "" {
		name = s.Name()
	}

	// Read file contents
	fb, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Get password for encryption
	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Encrypt file data using the filesystem's salt
	encrypted, err := EncryptGCM(fb, password, meta.Salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	// Check if encrypted file fits in slot
	if len(encrypted) >= MAX_FILE_SIZE {
		return fmt.Errorf("file too large after encryption: %d bytes (max %d)", len(encrypted), MAX_FILE_SIZE)
	}

	finalSize := len(encrypted)

	// FIX BUG-001: Use MAX_FILE_SIZE instead of META_FILE_SIZE for padding
	missing := MAX_FILE_SIZE - len(encrypted)
	encrypted = append(encrypted, make([]byte, missing)...)

	// Verify padding is correct (defensive check)
	if len(encrypted) != MAX_FILE_SIZE {
		return fmt.Errorf("internal error: padding calculation failed: %d != %d", len(encrypted), MAX_FILE_SIZE)
	}

	// Seek to file slot position
	seekPos := int64(META_FILE_SIZE) + (int64(nextFileIndex) * int64(MAX_FILE_SIZE))
	_, err = file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to file position: %w", err)
	}

	// Write encrypted file data
	n, err := file.Write(encrypted)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if n != len(encrypted) {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, len(encrypted))
	}

	// Sync to ensure data is persisted
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file data: %w", err)
	}

	// Update metadata
	meta.Files[nextFileIndex] = File{
		Name: name,
		Size: finalSize,
	}

	if err := WriteMeta(file, meta); err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	// Print success message
	Println("")
	Println("--------- New File ----------")
	Println(" Index:", nextFileIndex)
	Println(" Name:", name)
	Println(" Size (encrypted):", finalSize)
	Println(" Size (original):", len(fb))
	Println(" WriteAt:", META_FILE_SIZE+(nextFileIndex*MAX_FILE_SIZE))
	Println("-----------------------------")
	Println("")

	return nil
}
