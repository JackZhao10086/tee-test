//go:build darwin

package teeskscli

import (
	"path/filepath"
	"testing"
)

func TestDarwinKeychainPathUsesAppOwnedKeychain(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	keychainPath, err := darwinKeychainPath()
	if err != nil {
		t.Fatalf("keychain path: %v", err)
	}

	if filepath.Base(keychainPath) != "tee-test.keychain" {
		t.Fatalf("keychain path = %q, want tee-test.keychain basename", keychainPath)
	}
	if filepath.Dir(keychainPath) == "" {
		t.Fatalf("keychain path = %q, want directory", keychainPath)
	}
}
