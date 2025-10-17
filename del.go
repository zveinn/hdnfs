package hdnfs

import (
	"fmt"
)

func Del(file F, index int) error {
	// Validate index bounds
	if index < 0 || index >= TOTAL_FILES {
		return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, TOTAL_FILES-1)
	}

	// Read metadata
	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Check if file exists
	if meta.Files[index].Name == "" {
		return fmt.Errorf("no file exists at index %d", index)
	}

	// Clear metadata entry
	meta.Files[index].Size = 0
	meta.Files[index].Name = ""

	fmt.Printf("Deleting file at index %d...\n", index)

	// Seek to file slot
	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err = file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to file position: %w", err)
	}

	// Zero out the file slot
	buff := make([]byte, MAX_FILE_SIZE)
	n, err := file.Write(buff)
	if err != nil {
		return fmt.Errorf("failed to overwrite file slot: %w", err)
	}

	if n != MAX_FILE_SIZE {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, MAX_FILE_SIZE)
	}

	// Sync to ensure data is zeroed
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file deletion: %w", err)
	}

	// Update metadata
	if err := WriteMeta(file, meta); err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	fmt.Printf("Successfully deleted file at index %d\n", index)

	return nil
}
