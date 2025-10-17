package hdnfs

import (
	"fmt"
	"os"
)

func Get(file F, index int, path string) error {
	// Validate index bounds (FIX BUG-002)
	if index < 0 || index >= TOTAL_FILES {
		return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, TOTAL_FILES-1)
	}

	// Read metadata
	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Check if file exists at index
	df := meta.Files[index]
	if df.Name == "" {
		return fmt.Errorf("no file exists at index %d", index)
	}

	// Seek to file position
	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err = file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to file position: %w", err)
	}

	// Read encrypted file data
	buff := make([]byte, df.Size)
	n, err := file.Read(buff)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if n != df.Size {
		return fmt.Errorf("short read: read %d bytes, expected %d", n, df.Size)
	}

	// Get password for decryption
	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Decrypt file data
	decrypted, err := DecryptGCM(buff, password, meta.Salt)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	// Create output file (FIX BUG-004 with defer)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	// Write decrypted data
	n, err = f.Write(decrypted)
	if err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	if n != len(decrypted) {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, len(decrypted))
	}

	// Sync to ensure data is persisted
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync output file: %w", err)
	}

	fmt.Printf("Successfully extracted file '%s' (%d bytes) to %s\n", df.Name, len(decrypted), path)

	return nil
}
