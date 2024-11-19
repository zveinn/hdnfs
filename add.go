package hdnfs

import (
	"fmt"
	"os"
)

func Add(file *os.File, path string, name string, index int) {
	s, err := os.Stat(path)
	if err != nil {
		fmt.Println("Unable to stat file:", err)
		return
	}

	if len(name) > MAX_FILE_NAME_SIZE {
		fmt.Println("File name is too long, max length:", MAX_FILE_NAME_SIZE)
		return
	}

	meta := ReadMeta(file)
	nextFileIndex := 0
	foundIndex := false

	if index != OUT_OF_BOUNDS_INDEX && index < len(meta.Files) {
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
		fmt.Println("No more file slots available")
		return
	}

	if name == "" {
		name = s.Name()
	}

	fb, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Unable to read local file:", err)
		return
	}

	seekPos := META_FILE_SIZE + (nextFileIndex * MAX_FILE_SIZE)
	_, err = file.Seek(int64(seekPos), 0)
	if err != nil {
		fmt.Println("Unable to seek while writing: ", err)
		return
	}

	fb = Encrypt(fb, GetEncKey())
	if len(fb) >= MAX_FILE_SIZE {
		fmt.Println("File is too big, max size:", MAX_FILE_SIZE)
		return
	}
	finalSize := len(fb)
	missing := META_FILE_SIZE - len(fb)
	fb = append(fb, make([]byte, missing, missing)...)

	n, err := file.Write(fb)
	if err != nil {
		fmt.Println("Unable to write file: ", err)
		return
	}

	if n < len(fb) {
		fmt.Println("Short write: ", n, len(fb))
		return
	}

	fmt.Println("Creating new file:")
	fmt.Println("Index:", nextFileIndex)
	fmt.Println("Name:", name)
	fmt.Println("Size:", finalSize)
	fmt.Println("WriteAt:", META_FILE_SIZE+(nextFileIndex*MAX_FILE_SIZE))

	meta.Files[nextFileIndex] = File{
		Name: name,
		Size: finalSize,
	}

	WriteMeta(file, meta)
	return
}
