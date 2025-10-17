package hdnfs

import (
	"fmt"
	"strings"
)

func List(file F, filter string) error {

	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	Println("----------- FILE LIST -----------------")
	Printf(" %-5s %-5s %-10s\n", "index", "size", "name")
	Println("--------------------------------------")

	count := 0
	for i, v := range meta.Files {
		if v.Name == "" {
			continue
		}
		if filter != "" {
			if !strings.Contains(v.Name, filter) {
				continue
			}
		}
		Printf(" %-5d %-5d %-10s\n", i, v.Size, v.Name)
		count++
	}

	Println("--------------------------------------")
	Printf("Total files: %d\n", count)

	return nil
}
