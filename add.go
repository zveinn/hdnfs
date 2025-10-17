package hdnfs

import (
	"fmt"
	"os"
)

func Add(file F, path string, name string, index int) error {

	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if len(name) > MAX_FILE_NAME_SIZE {
		return fmt.Errorf("filename too long: %d (max %d)", len(name), MAX_FILE_NAME_SIZE)
	}

	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	nextFileIndex := 0
	foundIndex := false

	if index != OUT_OF_BOUNDS_INDEX {
		if index < 0 || index >= len(meta.Files) {
			return fmt.Errorf("index out of range: %d (valid range: 0-%d)", index, len(meta.Files)-1)
		}
		nextFileIndex = index
		foundIndex = true
	} else {

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

	if name == "" {
		name = s.Name()
	}

	fb, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	password, err := GetEncKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	encrypted, err := EncryptGCM(fb, password, meta.Salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	if len(encrypted) >= MAX_FILE_SIZE {
		return fmt.Errorf("file too large after encryption: %d bytes (max %d)", len(encrypted), MAX_FILE_SIZE)
	}

	finalSize := len(encrypted)

	missing := MAX_FILE_SIZE - len(encrypted)
	encrypted = append(encrypted, make([]byte, missing)...)

	if len(encrypted) != MAX_FILE_SIZE {
		return fmt.Errorf("internal error: padding calculation failed: %d != %d", len(encrypted), MAX_FILE_SIZE)
	}

	seekPos := int64(META_FILE_SIZE) + (int64(nextFileIndex) * int64(MAX_FILE_SIZE))
	_, err = file.Seek(seekPos, 0)
	if err != nil {
		return fmt.Errorf("failed to seek to file position: %w", err)
	}

	n, err := file.Write(encrypted)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	if n != len(encrypted) {
		return fmt.Errorf("short write: wrote %d bytes, expected %d", n, len(encrypted))
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file data: %w", err)
	}

	meta.Files[nextFileIndex] = File{
		Name: name,
		Size: finalSize,
	}

	if err := WriteMeta(file, meta); err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}

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
