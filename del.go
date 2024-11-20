package hdnfs

import (
	"fmt"
	"strconv"
)

func Del(file F, index int) {
	meta := ReadMeta(file)
	if index >= len(meta.Files) {
		PrintError("[index] out of range", nil)
		return
	}
	meta.Files[index].Size = 0
	meta.Files[index].Name = ""

	fmt.Println("deleting [index]:", index)

	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		PrintError("Unable to seek while writing: ", err)
		return
	}

	buff := make([]byte, MAX_FILE_SIZE, MAX_FILE_SIZE)
	n, err := file.Write(buff[0:MAX_FILE_SIZE])
	if err != nil {
		PrintError("Unable to write file: ", err)
		return
	}

	if n < MAX_FILE_SIZE {
		PrintError("Short write: "+strconv.Itoa(n), nil)
		return
	}

	WriteMeta(file, meta)
	return
}
