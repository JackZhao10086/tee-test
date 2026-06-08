package teesks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

func EncodePublicKey(publicKey any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func DecodePublicKey(encoded string) (any, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return publicKey, nil
	default:
		return nil, fmt.Errorf("public key is %T, expected ECDSA or RSA public key", publicKey)
	}
}

func EncodeSignature(signature []byte) string {
	return base64.StdEncoding.EncodeToString(signature)
}

func DecodeSignature(encoded string) ([]byte, error) {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return signature, nil
}

func VerifyMessage(message, encodedSignature, encodedPublicKey string) (bool, error) {
	publicKey, err := DecodePublicKey(encodedPublicKey)
	if err != nil {
		return false, err
	}

	signature, err := DecodeSignature(encodedSignature)
	if err != nil {
		return false, err
	}

	digest := sha256.Sum256([]byte(message))
	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(publicKey, digest[:], signature), nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("public key is %T, expected ECDSA or RSA public key", publicKey)
	}
}
