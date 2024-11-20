package hdnfs

import (
	"os"
)

func Get(file F, index int, path string) {
	meta := ReadMeta(file)
	df := meta.Files[index]

	seekPos := META_FILE_SIZE + (index * MAX_FILE_SIZE)
	_, err := file.Seek(int64(seekPos), 0)
	if err != nil {
		PrintError("Unable to seek while writing: ", err)
		return
	}

	buff := make([]byte, df.Size, df.Size)
	_, err = file.Read(buff[0:df.Size])
	if err != nil {
		PrintError("Unable to read file", err)
		return
	}

	f, err := os.Create(path)
	if err != nil {
		PrintError("Unable to create file", err)
		return
	}

	buff = Decrypt(buff, GetEncKey())
	_, err = f.Write(buff)
	if err != nil {
		PrintError("Unable to write file", err)
		return
	}
	return
}
