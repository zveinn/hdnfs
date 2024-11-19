package hdnfs

import (
	"fmt"
	"os"
)

func Del(file *os.File, index int) {
	meta := ReadMeta(file)
	if index >= len(meta.Files) {
		fmt.Println("Index out of range", index)
		return
	}
	meta.Files[index].Size = 0
	meta.Files[index].Name = ""

	fmt.Println("Deleting index:", index)

	// Delete unlocked file
	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		fmt.Println("Unable to seek while writing: ", err)
		return
	}

	buff := make([]byte, MAX_FILE_SIZE, MAX_FILE_SIZE)
	n, err := file.Write(buff[0:MAX_FILE_SIZE])
	if err != nil {
		fmt.Println("Unable to write file: ", err)
		return
	}

	if n < MAX_FILE_SIZE {
		fmt.Println("Short write: ", n, MAX_FILE_SIZE)
		return
	}

	// Delete locked file
	seekPos = META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err = file.Seek(int64(seekPos), 0)
	if err != nil {
		fmt.Println("Unable to seek while writing: ", err)
		return
	}

	n, err = file.Write(buff[0:MAX_FILE_SIZE])
	if err != nil {
		fmt.Println("Unable to write file: ", err)
		return
	}

	if n < MAX_FILE_SIZE {
		fmt.Println("Short write: ", n, MAX_FILE_SIZE)
		return
	}

	WriteMeta(file, meta)
	return
}
