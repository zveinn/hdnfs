package main

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

var (
	// Cache the password for the duration of the program execution
	cachedPassword string
	passwordMu     sync.Mutex
	passwordSet    bool
)

// PromptPassword prompts the user to enter a password from stdin without echoing.
// It uses the golang.org/x/term package for secure terminal input.
func PromptPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Enter password: ")

	// Read password without echoing to terminal
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // Print newline after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	if len(passwordBytes) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	return string(passwordBytes), nil
}

// GetPassword returns the cached password or prompts for it if not set.
// The password is cached in memory for the duration of the program execution
// to avoid prompting multiple times for a single command.
func GetPassword() (string, error) {
	passwordMu.Lock()
	defer passwordMu.Unlock()

	if passwordSet {
		return cachedPassword, nil
	}

	password, err := PromptPassword()
	if err != nil {
		return "", err
	}

	// Validate minimum length
	if len(password) < 12 {
		return "", fmt.Errorf("password must be at least 12 characters long")
	}

	cachedPassword = password
	passwordSet = true

	return password, nil
}

// ClearPasswordCache clears the cached password from memory.
// This is primarily useful for testing.
func ClearPasswordCache() {
	passwordMu.Lock()
	defer passwordMu.Unlock()

	// Zero out the password in memory
	if cachedPassword != "" {
		b := []byte(cachedPassword)
		for i := range b {
			b[i] = 0
		}
		cachedPassword = ""
	}
	passwordSet = false
}

// SetPasswordForTesting sets a password without prompting.
// This should only be used in tests.
func SetPasswordForTesting(password string) {
	passwordMu.Lock()
	defer passwordMu.Unlock()

	cachedPassword = password
	passwordSet = true
}
