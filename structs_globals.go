package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

const (
	META_FILE_SIZE      = 200_000
	MAX_FILE_SIZE       = 50_000
	MAX_FILE_NAME_SIZE  = 100
	TOTAL_FILES         = 1000
	ERASE_CHUNK_SIZE    = 1_000_000
	OUT_OF_BOUNDS_INDEX = 99999999

	MAGIC_SIZE    = 5
	VERSION_SIZE  = 1
	RESERVED_SIZE = 2
	SALT_SIZE     = 32
	LENGTH_SIZE   = 4
	CHECKSUM_SIZE = 32
	HEADER_SIZE   = MAGIC_SIZE + VERSION_SIZE + RESERVED_SIZE + SALT_SIZE + LENGTH_SIZE

	METADATA_VERSION = 2
)

const (
	MAGIC_STRING = "HDNFS"
)

const (
	ColorReset = "\033[0m"
	ColorBold  = "\033[1m"
	ColorDim   = "\033[2m"

	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"

	ColorBrightRed     = "\033[91m"
	ColorBrightGreen   = "\033[92m"
	ColorBrightYellow  = "\033[93m"
	ColorBrightBlue    = "\033[94m"
	ColorBrightMagenta = "\033[95m"

	// Light Blue (RGB: 173, 216, 230) - using 256-color palette
	ColorLightBlue = "\033[38;5;153m"
)

var HDNFS_ENV = "HDNFS"

var Silent = false

type Meta struct {
	Version int
	Salt    []byte
	Files   [TOTAL_FILES]File
}

type File struct {
	Name string
	Size int
}

type F interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Seek(int64, int) (int64, error)
	Name() string
	Sync() error
	Truncate(int64) error
	Stat() (os.FileInfo, error)
}

func PrintError(msg string, err error) {
	fmt.Println("----------------------------")
	fmt.Println("MSG:", msg)
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Println("----------------------------")
	fmt.Println(string(debug.Stack()))
	fmt.Println("----------------------------")
}

func Print(a ...interface{}) {
	if !Silent {
		fmt.Print(a...)
	}
}

func Println(a ...interface{}) {
	if !Silent {
		fmt.Println(a...)
	}
}

func Printf(format string, a ...interface{}) {
	if !Silent {
		fmt.Printf(format, a...)
	}
}

func C(color string, text string) string {
	return color + text + ColorReset
}

func PrintHeader(text string) {
	if !Silent {
		fmt.Println(C(ColorBold+ColorLightBlue, text))
	}
}

func PrintSeparator(length int) {
	if !Silent {
		fmt.Println(C(ColorDim+ColorLightBlue, strings.Repeat("─", length)))
	}
}

func PrintSuccess(text string) {
	if !Silent {
		fmt.Println(C(ColorLightBlue, text))
	}
}

func PrintLabel(label string, value interface{}) {
	if !Silent {
		fmt.Printf("%s %v\n", C(ColorBold+ColorLightBlue, label+":"), value)
	}
}
