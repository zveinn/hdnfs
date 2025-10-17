package hdnfs

import (
	"fmt"
	"os"
)

func Sync(src *os.File, dst *os.File) error {
	// Read source metadata
	srcMeta, err := ReadMeta(src)
	if err != nil {
		return fmt.Errorf("failed to read source metadata: %w", err)
	}

	// Write metadata to destination
	if err := WriteMeta(dst, srcMeta); err != nil {
		return fmt.Errorf("failed to write destination metadata: %w", err)
	}

	// Sync only non-empty file slots (optimization)
	syncedCount := 0
	for i, v := range srcMeta.Files {
		if v.Name == "" {
			continue
		}

		block, err := ReadBlock(src, i)
		if err != nil {
			return fmt.Errorf("failed to read block at index %d: %w", i, err)
		}

		if err := WriteBlock(dst, block, v.Name, i); err != nil {
			return fmt.Errorf("failed to write block at index %d: %w", i, err)
		}

		syncedCount++
		Printf("Synced file %d/%d: %s\n", syncedCount, len(srcMeta.Files), v.Name)
	}

	Printf("Sync complete: %d files synchronized\n", syncedCount)

	return nil
}

func ReadBlock(file *os.File, index int) ([]byte, error) {
	if index < 0 || index >= TOTAL_FILES {
		return nil, fmt.Errorf("index out of range: %d", index)
	}

	// Seek to block position
	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err := file.Seek(seekPos, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to block: %w", err)
	}

	// Read entire block
	block := make([]byte, MAX_FILE_SIZE)
	n, err := file.Read(block)
	if err != nil {
		return nil, fmt.Errorf("failed to read block: %w", err)
	}

	if n != MAX_FILE_SIZE {
		return nil, fmt.Errorf("short read: read %d bytes, expected %d", n, MAX_FILE_SIZE)
	}

	return block, nil
}

func WriteBlock(file *os.File, block []byte, name string, index int) error {
	if index < 0 || index >= TOTAL_FILES {
		return fmt.Errorf("index out of range: %d", index)
	}

	if len(block) != MAX_FILE_SIZE {
		return fmt.Errorf("invalid block size: %d (expected %d)", len(block), MAX_FILE_SIZE)
	}

	// Seek to block position
	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err := file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to block: %w", err)
	}

	// Write block
	n, err := file.Write(block)
	if err != nil {
		return fmt.Errorf("failed to write block: %w", err)
	}

	if n != len(block) {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, len(block))
	}

	// Sync to ensure data is persisted
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync block: %w", err)
	}

	return nil
}
