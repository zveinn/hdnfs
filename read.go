package main

import (
	"fmt"
	"os"
)

func Get(file F, index int, path string) error {

	if index < 0 || index >= TOTAL_FILES {
		return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, TOTAL_FILES-1)
	}

	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	df := meta.Files[index]
	if df.Name == "" {
		return fmt.Errorf("no file exists at index %d", index)
	}

	seekPos := int64(META_FILE_SIZE) + (int64(index) * int64(MAX_FILE_SIZE))
	_, err = file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to file position: %w", err)
	}

	buff := make([]byte, df.Size)
	n, err := file.Read(buff)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if n != df.Size {
		return fmt.Errorf("short read: read %d bytes, expected %d", n, df.Size)
	}

	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	decrypted, err := DecryptGCM(buff, password, meta.Salt)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	n, err = f.Write(decrypted)
	if err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	if n != len(decrypted) {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, len(decrypted))
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync output file: %w", err)
	}

	Printf("Successfully extracted file '%s' (%d bytes) to %s\n", df.Name, len(decrypted), path)

	return nil
}
