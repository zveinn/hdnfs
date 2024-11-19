package hdnfs

// META: 1_000_000:1_000_000*2
// FILE1: 1_000_000*2:1_000_000*3

var DISK = "/dev/sda"

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
