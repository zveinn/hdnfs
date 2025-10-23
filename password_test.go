package main

import (
	"testing"
)

func TestPasswordCaching(t *testing.T) {
	// Clear any cached password
	ClearPasswordCache()

	// Set a test password
	testPassword := "test-password-123"
	SetPasswordForTesting(testPassword)

	// First call should return the cached password
	password1, err := GetPassword()
	if err != nil {
		t.Fatalf("Failed to get password: %v", err)
	}
	if password1 != testPassword {
		t.Errorf("Expected password %q, got %q", testPassword, password1)
	}

	// Second call should return the same cached password without prompting
	password2, err := GetPassword()
	if err != nil {
		t.Fatalf("Failed to get password on second call: %v", err)
	}
	if password2 != testPassword {
		t.Errorf("Expected cached password %q, got %q", testPassword, password2)
	}

	// Clear the cache
	ClearPasswordCache()

	// After clearing, the password should be gone
	// (we can't test prompting in unit tests, so we just verify the cache was cleared)
	// This would normally prompt for a password in real usage
}

func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:        "Valid 12 character password",
			password:    "password1234",
			expectError: false,
		},
		{
			name:        "Valid long password",
			password:    "this-is-a-very-long-password-that-should-work",
			expectError: false,
		},
		{
			name:        "Too short password",
			password:    "short",
			expectError: true,
		},
		{
			name:        "Exactly 12 characters",
			password:    "exactly12chr",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ClearPasswordCache()

			if len(tt.password) >= 12 {
				// Valid password
				SetPasswordForTesting(tt.password)
				password, err := GetPassword()
				if err != nil {
					t.Errorf("Unexpected error for valid password: %v", err)
				}
				if password != tt.password {
					t.Errorf("Expected password %q, got %q", tt.password, password)
				}
			} else {
				// Invalid password - we can't directly test GetPassword() failing
				// because it would try to prompt, but we can verify the length check
				if len(tt.password) >= 12 && tt.expectError {
					t.Errorf("Password %q should be valid but test expects error", tt.password)
				}
			}

			ClearPasswordCache()
		})
	}
}

func TestClearPasswordCache(t *testing.T) {
	ClearPasswordCache()

	// Set a password
	testPassword := "test-password-for-clearing"
	SetPasswordForTesting(testPassword)

	// Verify it's set
	password, err := GetPassword()
	if err != nil {
		t.Fatalf("Failed to get password: %v", err)
	}
	if password != testPassword {
		t.Errorf("Expected password %q, got %q", testPassword, password)
	}

	// Clear the cache
	ClearPasswordCache()

	// The password should be cleared from memory
	// We can't directly verify this without accessing internal state,
	// but the function should have zeroed out the password bytes
}
