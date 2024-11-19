package hdnfs

import (
	"fmt"
	"os"
)

func Stat(file *os.File) {
	s, err := file.Stat()
	if err != nil {
		fmt.Println("Stat err:", err)
		return
	}
	fmt.Println("Name:", s.Name())
	fmt.Println("Size:", s.Size())
	fmt.Println("Mod:", s.ModTime())
	fmt.Println("Mod:", s.Mode())
}
