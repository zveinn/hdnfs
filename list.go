package hdnfs

import (
	"fmt"
	"os"
)

func List(file *os.File) {
	m := ReadMeta(file)
	fmt.Println("----------- FILE LIST -----------------")
	for i, v := range m.Files {
		if v.Name != "" {
			fmt.Println(i, v.Name, v.Size)
		}
	}
	fmt.Println("--------------------------------------")
}
