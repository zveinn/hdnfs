package hdnfs

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
)

var (
	device string
	remove string

	start int64

	diskPointer F
)

func Main() {
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
		var startIndex int
		if len(os.Args) > 3 {
			startIndex, err = strconv.Atoi(os.Args[3])
			if err != nil {
				printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
			}
		}
		Overwrite(file, int64(startIndex), math.MaxUint64)
	case "init":
		mode := "device"
		if len(os.Args) > 3 {
			mode = os.Args[3]
		}
		InitMeta(file, mode)
	case "add":
		var index int
		var path, name string
		if len(os.Args) < 5 {
			printHelpMenu("not enough parameters")
		}
		if len(os.Args) > 5 {
			index, err = strconv.Atoi(os.Args[5])
			if err != nil {
				printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
			}
		} else {
			index = OUT_OF_BOUNDS_INDEX
		}
		path = os.Args[3]
		if path == "" {
			printHelpMenu("missing [path]")
		}
		name = os.Args[4]
		if name == "" {
			printHelpMenu("missing [new_name]")
		}
		Add(file, path, name, index)
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
		Get(file, index, path)
	case "del":
		index, err := strconv.Atoi(os.Args[3])
		if err != nil {
			printHelpMenu(fmt.Sprintf("invalid [index]: %s", err))
		}
		Del(file, index)
	case "list":
		filter := ""
		if len(os.Args) > 3 {
			filter = os.Args[3]
		}
		List(file, filter)
	case "stat":
		Stat(file)
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

		Sync(file, dst)
	default:
		printHelpMenu("unknown [cmd]")
	}
}

func printHelpMenu(msg string) {
	if msg != "" {
		fmt.Println("------------------------------------")
		fmt.Println("")
		fmt.Println("MSG: ", msg)
		fmt.Println("")
	}
	fmt.Println("------------------------------------")

	fmt.Println("")
	fmt.Println(" __ Settings __ ")
	fmt.Println(" MAX_FILE_NAME_SIZE: ", MAX_FILE_NAME_SIZE)
	fmt.Println(" MAX_FILE_SIZE: ", MAX_FILE_SIZE)
	fmt.Println(" META_FILE_SIZE: ", META_FILE_SIZE)
	fmt.Println(" Total File Capacity: ", 1000)
	fmt.Println("")
	fmt.Println(" __ Available Modes __ ")
	fmt.Println(" Device(default): Uses a usb/disk device for storage")
	fmt.Println(" File: uses a normal file for storage")
	fmt.Println("")
	fmt.Println(" __ General cli pattern __")
	fmt.Println("  $ ./hdnfs [device] [cmd] [param1] [param2] [param3] ...")

	fmt.Println("")
	fmt.Println("")
	fmt.Println(" Erase data from the drive starting at [index]")
	fmt.Println("  $ ./hdnfs [device] erase [index]")
	fmt.Println("")

	fmt.Println(" Intialize the file system")
	fmt.Println("  $ ./hdnfs [device] init [mode:optional]")
	fmt.Println("")

	fmt.Println(" Add a file from [path] as [new_name]")
	fmt.Println(" You can overwrite files at [index] if specified")
	fmt.Println("  $ ./hdnfs [device] add [path] [new_name] [index:optionl]")
	fmt.Println("")

	fmt.Println(" Delete file at [index]")
	fmt.Println("  $ ./hdnfs [device] del [index]")
	fmt.Println("")

	fmt.Println(" Get file at [index] to [path]")
	fmt.Println("  $ ./hdnfs [device] get [index] [path]")
	fmt.Println("")

	fmt.Println(" List all files with an optional [filter]")
	fmt.Println("  $ ./hdnfs [device] list [filter:optional]")
	fmt.Println("")

	fmt.Println(" Stat the drive")
	fmt.Println("  $ ./hdnfs [device] stat")
	fmt.Println("")

	fmt.Println(" Sync metadata and files from [device] to [target_device]")
	fmt.Println(" NOTE: the [target_device] also needs to be erased before using")
	fmt.Println("  $ ./hdnfs [device] sync [target_device]")
	fmt.Println("")

	fmt.Println("------------------------------------")
	os.Exit(1)
}
