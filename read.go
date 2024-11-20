package hdnfs

import (
	"fmt"
	"os"
)

func Get(file *os.File, index int, path string) {
	meta := ReadMeta(file)
	df := meta.Files[index]

	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		fmt.Println("Unable to seek while writing: ", err)
		return
	}

	buff := make([]byte, df.Size, df.Size)
	_, err = file.Read(buff[0:df.Size])
	if err != nil {
		fmt.Println("Unable to read file", err)
		return
	}

	f, err := os.Create(path)
	if err != nil {
		fmt.Println("Unable to create file", err)
		return
	}

	buff = Decrypt(buff, GetEncKey())
	_, err = f.Write(buff)
	if err != nil {
		fmt.Println("Unable to write file", err)
		return
	}
	return
}
