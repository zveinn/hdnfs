package hdnfs

import (
	"fmt"
	"os"
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
		fmt.Println("Unable to seek while writing: ", err)
		return
	}

	block = make([]byte, MAX_FILE_SIZE, MAX_FILE_SIZE)
	n, err := file.Read(block[0:MAX_FILE_SIZE])
	if err != nil {
		fmt.Println("Unable to read file", err)
		return
	}

	if n != len(block) {
		fmt.Println("Unable to read block during sync", n, len(block))
		return
	}

	return
}

func WriteBlock(file *os.File, block []byte, name string, index int) {
	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		fmt.Println("Unable to seek while writing: ", err)
		return
	}

	n, err := file.Write(block)
	if err != nil {
		fmt.Println("Unable to write file: ", err)
		return
	}

	if n < len(block) {
		fmt.Println("Short write: ", n, len(block))
		return
	}

	fmt.Println("Synced Index:", index)
	return
}
