//go:build !darwin

package teeskscli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/facebookincubator/sks"
	sksattest "github.com/facebookincubator/sks/attest"
)

func secureHardwareVendorData() (*sksattest.SecureHardwareVendorData, error) {
	return sks.GetSecureHardwareVendorData()
}

func createKey(label, tag string) (*keyResult, error) {
	key, err := sks.NewKey(label, tag, false, true, nil)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	publicKey, err := publicKeyFromSigner(key)
	if err != nil {
		return nil, err
	}
	return &keyResult{PublicKey: publicKey}, nil
}

func signWithKey(label, tag, message string) (*signResult, error) {
	key, err := sks.NewKey(label, tag, false, true, nil)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	defer key.Close()

	digest := sha256.Sum256([]byte(message))
	signature, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	publicKey, err := publicKeyFromSigner(key)
	if err != nil {
		return nil, err
	}
	return &signResult{
		Signature: signature,
		PublicKey: publicKey,
	}, nil
}

func publicKeyFromSigner(signer crypto.Signer) (*ecdsa.PublicKey, error) {
	publicKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, expected *ecdsa.PublicKey", signer.Public())
	}
	return publicKey, nil
}
