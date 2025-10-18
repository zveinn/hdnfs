package main

import (
	"fmt"
)

func Del(file F, index int) error {

	if index < 0 || index >= TOTAL_FILES {
		return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, TOTAL_FILES-1)
	}

	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	if meta.Files[index].Name == "" {
		return fmt.Errorf("no file exists at index %d", index)
	}

	meta.Files[index].Size = 0
	meta.Files[index].Name = ""

	Printf("Deleting file at index %d...\n", index)

	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err = file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to file position: %w", err)
	}

	buff := make([]byte, MAX_FILE_SIZE)
	n, err := file.Write(buff)
	if err != nil {
		return fmt.Errorf("failed to overwrite file slot: %w", err)
	}

	if n != MAX_FILE_SIZE {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, MAX_FILE_SIZE)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file deletion: %w", err)
	}

	if err := WriteMeta(file, meta); err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	Printf("Successfully deleted file at index %d\n", index)

	return nil
}
