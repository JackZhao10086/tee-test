package teesks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestEncodePublicKeyRoundTrip(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	encoded, err := EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}

	publicKey, err := DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("decoded public key is %T, want *ecdsa.PublicKey", publicKey)
	}

	if ecdsaPublicKey.X.Cmp(privateKey.PublicKey.X) != 0 || ecdsaPublicKey.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		t.Fatal("decoded public key does not match original")
	}
}

func TestVerifySignaturePair(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := "hello tee"
	digest := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	encodedPublicKey, err := EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	encodedSignature := EncodeSignature(signature)

	ok, err := VerifyMessage(message, encodedSignature, encodedPublicKey)
	if err != nil {
		t.Fatalf("verify message: %v", err)
	}
	if !ok {
		t.Fatal("expected signature and public key to verify")
	}
}

func TestVerifySignaturePairRejectsDifferentMessage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	digest := sha256.Sum256([]byte("hello tee"))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	encodedPublicKey, err := EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}

	ok, err := VerifyMessage("goodbye tee", EncodeSignature(signature), encodedPublicKey)
	if err != nil {
		t.Fatalf("verify message: %v", err)
	}
	if ok {
		t.Fatal("expected signature verification to fail for a different message")
	}
}

func TestVerifyRSASignaturePair(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := "hello keychain"
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	encodedPublicKey, err := EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}

	ok, err := VerifyMessage(message, EncodeSignature(signature), encodedPublicKey)
	if err != nil {
		t.Fatalf("verify message: %v", err)
	}
	if !ok {
		t.Fatal("expected RSA signature and public key to verify")
	}
}
