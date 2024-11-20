package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/zveinn/hdnfs"
	"golang.org/x/term"
)

// EXPERIMENTAL
// EXPERIMENTAL
// EXPERIMENTAL
// EXPERIMENTAL
// EXPERIMENTAL
// EXPERIMENTAL
// EXPERIMENTAL
func main() {
	fmt.Println(os.Getpid())
	key, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if len(key) < 32 {
		fmt.Println("TRY AGAIN")
		return
	}

	hdnfs.KEY = key

AGAIN:
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		text := scanner.Text()
		args := strings.Split(text, " ")
		args = append([]string{"*"}, args...)
		if args[len(args)-1] == "" {
			args = args[:len(args)-1]
		}
		fmt.Println(os.Args)
		os.Args = args
		hdnfs.Main()
		goto AGAIN
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

// 01234567890123456789012345678900
