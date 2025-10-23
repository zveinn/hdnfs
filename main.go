package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

var device string

func main() {
	for i, arg := range os.Args {
		if arg == "--silent" || arg == "-silent" {
			Silent = true

			os.Args = append(os.Args[:i], os.Args[i+1:]...)
			break
		}
	}

	if len(os.Args) < 2 {
		printHelpMenu("")
	}
	if os.Args[1] == "help" || os.Args[1] == "-help" || os.Args[1] == "--help" {
		printHelpMenu("")
	}

	if len(os.Args) < 3 {
		printHelpMenu("not enough parameters")
	}

	device = os.Args[1]
	if device == "" {
		printHelpMenu("[device] missing")
	}
	cmd := os.Args[2]
	if cmd == "" {
		printHelpMenu("[cmd] missing")
	}

	file, err := os.OpenFile(device, os.O_RDWR, 0o777)
	if err != nil {
		log.Fatalf("unable to open [device]: %v", err)
	}
	defer file.Close()

	switch cmd {
	case "erase":
		s, err := file.Stat()
		if err != nil {
			log.Fatalf("failed to stat device: %v", err)
		}

		if s.Mode().IsRegular() {
			if err := file.Truncate(0); err != nil {
				log.Fatalf("Erase failed: %v", err)
			}
			PrintSuccess("File truncated successfully")
		} else {
			if err := OverwriteDevice(file); err != nil {
				log.Fatalf("Erase failed: %v", err)
			}
		}
	case "init":
		mode := "device"
		if len(os.Args) > 3 {
			mode = os.Args[3]
		}
		if err := InitMeta(file, mode); err != nil {
			log.Fatalf("Initialization failed: %v", err)
		}
		PrintSuccess("Filesystem initialized successfully")
	case "add":
		var index int
		var path string
		if len(os.Args) < 4 {
			printHelpMenu("not enough parameters")
		}
		path = os.Args[3]
		if path == "" {
			printHelpMenu("missing [path]")
		}
		// Index is optional (os.Args[4])
		if len(os.Args) > 4 {
			index, err = strconv.Atoi(os.Args[4])
			if err != nil {
				printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
			}
		} else {
			index = OUT_OF_BOUNDS_INDEX
		}
		if err := Add(file, path, index); err != nil {
			log.Fatalf("Add failed: %v", err)
		}
	case "get":
		var path string
		if len(os.Args) < 5 {
			printHelpMenu("not enough parameters")
		}
		index, err := strconv.Atoi(os.Args[3])
		if err != nil {
			printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
		}
		path = os.Args[4]
		if err := Get(file, index, path); err != nil {
			log.Fatalf("Get failed: %v", err)
		}
	case "del":
		index, err := strconv.Atoi(os.Args[3])
		if err != nil {
			printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
		}
		if err := Del(file, index); err != nil {
			log.Fatalf("Delete failed: %v", err)
		}
	case "list":
		filter := ""
		if len(os.Args) > 3 {
			filter = os.Args[3]
		}
		if err := List(file, filter); err != nil {
			log.Fatalf("List failed: %v", err)
		}
	case "stat":
		if err := Stat(file); err != nil {
			log.Fatalf("Stat failed: %v", err)
		}
	case "sync":

		if len(os.Args) < 4 {
			printHelpMenu("not enough parameters")
			return
		}
		if os.Args[3] == "" {
			printHelpMenu("[device] missing")
			return
		}

		dst, err := os.OpenFile(os.Args[3], os.O_RDWR, 0o777)
		if err != nil {
			log.Fatalf("unable to open [target_device]: %v", err)
		}
		defer dst.Close()

		if err := Sync(file, dst); err != nil {
			log.Fatalf("Sync failed: %v", err)
		}
	case "search-name":
		if len(os.Args) < 4 {
			printHelpMenu("not enough parameters")
		}
		phrase := os.Args[3]
		if phrase == "" {
			printHelpMenu("missing [phrase]")
		}
		if err := SearchName(file, phrase); err != nil {
			log.Fatalf("Name search failed: %v", err)
		}
	case "search":
		if len(os.Args) < 4 {
			printHelpMenu("not enough parameters")
		}
		phrase := os.Args[3]
		if phrase == "" {
			printHelpMenu("missing [phrase]")
		}
		index := OUT_OF_BOUNDS_INDEX
		if len(os.Args) > 4 {
			index, err = strconv.Atoi(os.Args[4])
			if err != nil {
				printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
			}
		}
		if err := SearchContent(file, phrase, index); err != nil {
			log.Fatalf("Content search failed: %v", err)
		}
	default:
		printHelpMenu("unknown [cmd]")
	}
}

func printHelpMenu(msg string) {
	if msg != "" {
		fmt.Println()
		fmt.Printf("%s\n", C(ColorBold+ColorRed, "ERROR: "+msg))
		fmt.Println()
	}

	fmt.Println()
	fmt.Printf("%s\n", C(ColorBold+ColorLightBlue, "HDNFS - Hidden Encrypted File System"))
	fmt.Printf("%s\n\n", C(ColorDim, "Secure, encrypted file storage with AES-256-GCM"))

	// Settings Section
	fmt.Printf("%s\n", C(ColorBold+ColorLightBlue, "SYSTEM LIMITS"))
	PrintSeparator(60)
	fmt.Printf(" %-25s %s\n", C(ColorLightBlue, "Max filename length:"), C(ColorWhite, fmt.Sprintf("%d characters", MAX_FILE_NAME_SIZE)))
	fmt.Printf(" %-25s %s\n", C(ColorLightBlue, "Max file size:"), C(ColorWhite, fmt.Sprintf("%d bytes (~49 KB)", MAX_FILE_SIZE)))
	fmt.Printf(" %-25s %s\n", C(ColorLightBlue, "Total file capacity:"), C(ColorWhite, "1000 files"))
	fmt.Printf(" %-25s %s\n", C(ColorLightBlue, "Metadata size:"), C(ColorWhite, fmt.Sprintf("%d bytes (~195 KB)", META_FILE_SIZE)))
	fmt.Println()

	// Usage Pattern
	fmt.Printf("%s\n", C(ColorBold+ColorLightBlue, "USAGE"))
	PrintSeparator(60)
	fmt.Printf(" %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorBrightBlue, "[command]"),
		C(ColorDim, "[parameters...]"))

	// Flags
	fmt.Printf("%s\n", C(ColorBold+ColorLightBlue, "FLAGS"))
	PrintSeparator(60)
	fmt.Printf(" %s  %s\n\n",
		C(ColorWhite, "--silent"),
		C(ColorDim, "Suppress informational output"))

	// Commands
	fmt.Printf("%s\n", C(ColorBold+ColorLightBlue, "COMMANDS"))
	PrintSeparator(60)

	// Init
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "init"))
	fmt.Printf("   %s\n", C(ColorDim, "Initialize a new encrypted filesystem"))
	fmt.Printf("   %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "init"),
		C(ColorDim, "[file|device]"))

	// Add
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "add"))
	fmt.Printf("   %s\n", C(ColorDim, "Encrypt and add a file to the filesystem"))
	fmt.Printf("   %s %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "add"),
		C(ColorBrightBlue, "[path]"),
		C(ColorDim, "[index]"))

	// List
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "list"))
	fmt.Printf("   %s\n", C(ColorDim, "List all files in the filesystem"))
	fmt.Printf("   %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "list"),
		C(ColorDim, "[filter]"))

	// Get
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "get"))
	fmt.Printf("   %s\n", C(ColorDim, "Extract and decrypt a file"))
	fmt.Printf("   %s %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "get"),
		C(ColorBrightBlue, "[index]"),
		C(ColorBrightBlue, "[output_path]"))

	// Delete
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "del"))
	fmt.Printf("   %s\n", C(ColorDim, "Delete a file and zero its slot"))
	fmt.Printf("   %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "del"),
		C(ColorBrightBlue, "[index]"))

	// Search Name
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "search-name"))
	fmt.Printf("   %s\n", C(ColorDim, "Search filenames (fast, no decryption)"))
	fmt.Printf("   %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "search-name"),
		C(ColorBrightBlue, "[phrase]"))

	// Search Content
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "search"))
	fmt.Printf("   %s\n", C(ColorDim, "Search file contents (decrypts and scans)"))
	fmt.Printf("   %s %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "search"),
		C(ColorBrightBlue, "[phrase]"),
		C(ColorDim, "[index]"))

	// Stat
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "stat"))
	fmt.Printf("   %s\n", C(ColorDim, "Show device statistics"))
	fmt.Printf("   %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "stat"))

	// Sync
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "sync"))
	fmt.Printf("   %s\n", C(ColorDim, "Synchronize all files to another device"))
	fmt.Printf("   %s %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "sync"),
		C(ColorBrightBlue, "[target_device]"))

	// Erase
	fmt.Printf(" %s\n", C(ColorBold+ColorWhite, "erase"))
	fmt.Printf("   %s\n", C(ColorDim, "Erase all data (truncate file or overwrite device)"))
	fmt.Printf("   %s %s %s\n\n",
		C(ColorWhite, "./hdnfs"),
		C(ColorBrightBlue, "[device]"),
		C(ColorWhite, "erase"))

	// Examples
	fmt.Printf("%s\n", C(ColorBold+ColorLightBlue, "EXAMPLES"))
	PrintSeparator(60)
	fmt.Printf(" %s\n", C(ColorDim, "Initialize a file-based storage:"))
	fmt.Printf("   %s\n\n", C(ColorWhite, "./hdnfs storage.hdnfs init file"))

	fmt.Printf(" %s\n", C(ColorDim, "Add a file:"))
	fmt.Printf("   %s\n\n", C(ColorWhite, "./hdnfs storage.hdnfs add secret.txt"))

	fmt.Printf(" %s\n", C(ColorDim, "List all files:"))
	fmt.Printf("   %s\n\n", C(ColorWhite, "./hdnfs storage.hdnfs list"))

	fmt.Printf(" %s\n", C(ColorDim, "Extract a file:"))
	fmt.Printf("   %s\n\n", C(ColorWhite, "./hdnfs storage.hdnfs get 0 /tmp/recovered.txt"))

	PrintSeparator(60)
	fmt.Printf("\n%s %s\n\n",
		C(ColorBold+ColorLightBlue, "Environment:"),
		C(ColorWhite, "Set HDNFS variable with your encryption password"))

	os.Exit(1)
}
