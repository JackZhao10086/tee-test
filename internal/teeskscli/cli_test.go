package teeskscli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	sksattest "github.com/facebookincubator/sks/attest"

	"tee-test/internal/teesks"
)

func TestCheckSupportReportsTPMDevice(t *testing.T) {
	output := CheckSupport("linux", func() (*sksattest.SecureHardwareVendorData, error) {
		return &sksattest.SecureHardwareVendorData{
			IsTPM20CompliantDevice: true,
			VendorName:             "test vendor",
			VendorInfo:             "test info",
			Version:                2,
		}, nil
	})

	if !output.Supported {
		t.Fatal("expected TPM 2.0 device to be supported")
	}
	if output.Status != "supported" {
		t.Fatalf("status = %q, want supported", output.Status)
	}
	if output.VendorName != "test vendor" {
		t.Fatalf("vendor name = %q, want test vendor", output.VendorName)
	}
}

func TestCheckSupportReportsProbeFailure(t *testing.T) {
	output := CheckSupport("linux", func() (*sksattest.SecureHardwareVendorData, error) {
		return nil, errors.New("open /dev/tpmrm0: no such file")
	})

	if output.Supported {
		t.Fatal("expected probe failure to be unsupported")
	}
	if output.Status != "unsupported" {
		t.Fatalf("status = %q, want unsupported", output.Status)
	}
	if output.Reason == "" {
		t.Fatal("expected reason to explain probe failure")
	}
}

func TestRunVerifyWritesValidJSON(t *testing.T) {
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
	publicKey, err := teesks.EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}

	var stdout bytes.Buffer
	err = Run([]string{
		"verify",
		"--message", message,
		"--signature", teesks.EncodeSignature(signature),
		"--public-key", publicKey,
	}, &stdout)
	if err != nil {
		t.Fatalf("run verify: %v", err)
	}

	var output VerifyOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if !output.Valid {
		t.Fatal("expected verify output to be valid")
	}
}

func TestRunExistsRequiresLabelAndTag(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run([]string{"exists", "--label", "only-label"}, &stdout); err == nil {
		t.Fatal("expected exists without tag to fail")
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run([]string{"bogus"}, &stdout); err == nil {
		t.Fatal("expected unknown command to fail")
	}
}
