package hdnfs

import (
	"fmt"
	"strings"
)

func List(file F, filter string) {
	m := ReadMeta(file)
	fmt.Println("----------- FILE LIST -----------------")
	fmt.Printf(" %-5s %-5s %-10s\n", "index", "size", "name")
	fmt.Println("--------------------------------------")
	for i, v := range m.Files {
		if v.Name == "" {
			continue
		}
		if filter != "" {
			if !strings.Contains(v.Name, filter) {
				continue
			}
		}
		fmt.Printf(" %-5d %-5d %-10s\n", i, v.Size, v.Name)
	}
	fmt.Println("--------------------------------------")
}
