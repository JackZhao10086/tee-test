//go:build !windows && !darwin

package teeskscli

import "fmt"

func lookupKey(label, tag string) (*keyLookupResult, error) {
	return nil, fmt.Errorf("exists command is only implemented for Windows CNG keys and macOS Keychain metadata")
}
