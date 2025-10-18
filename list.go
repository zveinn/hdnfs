package main

import (
	"fmt"
	"strings"
)

func List(file F, filter string) error {
	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	PrintHeader("FILE LIST")
	PrintSeparator(70)
	Printf(" %s  %s  %s\n",
		C(ColorBold+ColorLightBlue, "INDEX"),
		C(ColorBold+ColorLightBlue, "SIZE      "),
		C(ColorBold+ColorLightBlue, "NAME"))
	PrintSeparator(70)

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
		Printf(" %s  %s  %s\n",
			C(ColorBrightBlue, fmt.Sprintf("%-5d", i)),
			C(ColorLightBlue, fmt.Sprintf("%-10s", fmt.Sprintf("%d bytes", v.Size))),
			C(ColorWhite, v.Name))
		count++
	}

	PrintSeparator(70)
	Printf("\n%s %s\n", C(ColorBold+ColorLightBlue, "Total files:"), C(ColorWhite, fmt.Sprintf("%d", count)))

	return nil
}
