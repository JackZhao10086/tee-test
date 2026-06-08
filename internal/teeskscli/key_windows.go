//go:build windows

package teeskscli

import (
	"strings"

	tpm "github.com/google/certtostore"
)

const (
	windowsKeyStorageProvider = "Microsoft Platform Crypto Provider"
	windowsKeyNotFoundCode    = "80090016"
	windowsTagLookupNote      = "Windows sks backend uses label as the CNG key container name; tag is reported but not part of the system lookup"
)

func lookupKey(label, tag string) (*keyLookupResult, error) {
	certStore, err := tpm.OpenWinCertStoreCurrentUser(
		windowsKeyStorageProvider,
		label,
		[]string{},
		[]string{},
		false,
	)
	if err != nil {
		return nil, err
	}
	defer certStore.Close()

	key, err := certStore.Key()
	if err != nil {
		if strings.Contains(err.Error(), windowsKeyNotFoundCode) {
			return &keyLookupResult{
				Exists: false,
				Note:   windowsTagLookupNote,
			}, nil
		}
		return nil, err
	}
	if key == nil {
		return &keyLookupResult{
			Exists: false,
			Note:   windowsTagLookupNote,
		}, nil
	}

	return &keyLookupResult{
		Exists:    true,
		PublicKey: key.Public(),
		Note:      windowsTagLookupNote,
	}, nil
}
