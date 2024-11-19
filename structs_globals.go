package hdnfs

import "os"

// META: 1_000_000:1_000_000*2
// FILE1: 1_000_000*2:1_000_000*3

var (
	DISK      = "/dev/sda"
	HDNFS_ENV = "HDNFS"
)

func GetEncKey() (key []byte) {
	k := os.Getenv(HDNFS_ENV)
	if k == "" {
		panic("HDNFS not defined")
	}

	if len(k) < 32 {
		panic("HDNFS less then 32 bytes long")
	}

	key = []byte(k)

	return
}

const (
	META_FILE_SIZE      = 200_000
	MAX_FILE_SIZE       = 50_000
	MAX_FILE_NAME_SIZE  = 100
	OUT_OF_BOUNDS_INDEX = 99999999
)

type Meta struct {
	Files [1000]File
}

// 8:8:84
type File struct {
	Name string
	Size int
}
