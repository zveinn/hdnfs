package hdnfs

import (
	"fmt"
	"os"
	"strconv"
)

func Sync(src *os.File, dst *os.File) {
	srcMeta := ReadMeta(src)
	WriteMeta(dst, srcMeta)

	for i, v := range srcMeta.Files {
		WriteBlock(
			dst,
			ReadBlock(src, i),
			v.Name,
			i,
		)
	}
}

func ReadBlock(file *os.File, index int) (block []byte) {
	// meta := ReadMeta(file)
	// df := meta.Files[index]

	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		PrintError("Unable to seek while writing", err)
		return
	}

	block = make([]byte, MAX_FILE_SIZE, MAX_FILE_SIZE)
	n, err := file.Read(block[0:MAX_FILE_SIZE])
	if err != nil {
		PrintError("Unable to read file", err)
		return
	}

	if n != len(block) {
		PrintError("Unable to read block during sync: "+strconv.Itoa(n), nil)
		return
	}

	return
}

func WriteBlock(file *os.File, block []byte, name string, index int) {
	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		PrintError("Unable to seek while writing: ", err)
		return
	}

	n, err := file.Write(block)
	if err != nil {
		PrintError("Unable to write file: ", err)
		return
	}

	if n < len(block) {
		PrintError("Short write: "+strconv.Itoa(n), nil)
		return
	}

	fmt.Println("Synced [index]:", index)
	return
}
