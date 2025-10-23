package main

import (
	"fmt"
	"strings"
	"time"
)

func List(file F, filter string) error {
	meta, err := ReadMeta(file)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	PrintHeader("FILE LIST")
	PrintSeparator(100)
	Printf(" %s  %s  %s  %s\n",
		C(ColorBold+ColorLightBlue, "INDEX"),
		C(ColorBold+ColorLightBlue, "SIZE      "),
		C(ColorBold+ColorLightBlue, "CREATED            "),
		C(ColorBold+ColorLightBlue, "NAME"))
	PrintSeparator(100)

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
		created := "N/A"
		if v.Created > 0 {
			created = time.Unix(v.Created, 0).Format("2006-01-02 15:04:05")
		}
		Printf(" %s  %s  %s  %s\n",
			C(ColorBrightBlue, fmt.Sprintf("%-5d", i)),
			C(ColorLightBlue, fmt.Sprintf("%-10s", fmt.Sprintf("%d bytes", v.Size))),
			C(ColorCyan, fmt.Sprintf("%-19s", created)),
			C(ColorWhite, v.Name))
		count++
	}

	PrintSeparator(100)
	Printf("\n%s %s\n", C(ColorBold+ColorLightBlue, "Total files:"), C(ColorWhite, fmt.Sprintf("%d", count)))

	return nil
}
