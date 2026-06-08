package teeskscli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"

	sksattest "github.com/facebookincubator/sks/attest"

	"tee-test/internal/teesks"
)

type CheckOutput struct {
	Supported         bool   `json:"supported"`
	Status            string `json:"status"`
	Backend           string `json:"backend,omitempty"`
	Platform          string `json:"platform"`
	PlatformSupported bool   `json:"platform_supported"`
	Reason            string `json:"reason,omitempty"`
	VendorName        string `json:"vendor_name,omitempty"`
	VendorInfo        string `json:"vendor_info,omitempty"`
	Version           uint8  `json:"version,omitempty"`
}

type createOutput struct {
	Label     string `json:"label"`
	Tag       string `json:"tag"`
	PublicKey string `json:"public_key"`
}

type signOutput struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

type VerifyOutput struct {
	Valid bool `json:"valid"`
}

func Run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError("missing command")
	}

	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout)
	case "create":
		return runCreate(args[1:], stdout)
	case "sign":
		return runSign(args[1:], stdout)
	case "verify":
		return runVerify(args[1:], stdout)
	default:
		return usageError(fmt.Sprintf("unknown command %q", args[0]))
	}
}

func runCheck(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("check does not accept positional arguments")
	}

	return writeJSON(stdout, CheckSupport(runtime.GOOS, secureHardwareVendorData))
}

func CheckSupport(goos string, probe func() (*sksattest.SecureHardwareVendorData, error)) CheckOutput {
	output := CheckOutput{
		Platform: goos,
	}

	switch goos {
	case "linux", "windows":
		output.PlatformSupported = true
		output.Backend = "sks"
	case "darwin":
		output.PlatformSupported = true
		output.Supported = true
		output.Status = "supported"
		output.Backend = "keychain"
		output.Reason = "uses macOS Keychain non-extractable keys, not Secure Enclave attestation"
		return output
	default:
		output.Status = "unsupported"
		output.Reason = "sks documents support for Linux TPM 2.0, Windows TPM 2.0, and macOS Secure Enclave only"
		return output
	}

	data, err := probe()
	if err != nil {
		output.Status = "unsupported"
		output.Reason = err.Error()
		return output
	}

	output.VendorName = data.VendorName
	output.VendorInfo = data.VendorInfo
	output.Version = data.Version
	if !data.IsTPM20CompliantDevice {
		output.Status = "unsupported"
		output.Reason = "secure hardware probe did not report a TPM 2.0 compliant device"
		return output
	}

	output.Supported = true
	output.Status = "supported"
	return output
}

func runCreate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	label := flags.String("label", "", "key label")
	tag := flags.String("tag", "", "key tag")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := requireLabelTag(*label, *tag); err != nil {
		return err
	}

	key, err := createKey(*label, *tag)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	encodedPublicKey, err := teesks.EncodePublicKey(key.PublicKey)
	if err != nil {
		return err
	}

	return writeJSON(stdout, createOutput{
		Label:     *label,
		Tag:       *tag,
		PublicKey: encodedPublicKey,
	})
}

func runSign(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	label := flags.String("label", "", "key label")
	tag := flags.String("tag", "", "key tag")
	message := flags.String("message", "", "message to sign")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := requireLabelTag(*label, *tag); err != nil {
		return err
	}
	if *message == "" {
		return errors.New("missing --message")
	}

	result, err := signWithKey(*label, *tag, *message)
	if err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	encodedPublicKey, err := teesks.EncodePublicKey(result.PublicKey)
	if err != nil {
		return err
	}

	return writeJSON(stdout, signOutput{
		Message:   *message,
		Signature: teesks.EncodeSignature(result.Signature),
		PublicKey: encodedPublicKey,
	})
}

func runVerify(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	message := flags.String("message", "", "message that was signed")
	signature := flags.String("signature", "", "base64 ASN.1 ECDSA signature")
	publicKey := flags.String("public-key", "", "base64 DER public key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *message == "" {
		return errors.New("missing --message")
	}
	if *signature == "" {
		return errors.New("missing --signature")
	}
	if *publicKey == "" {
		return errors.New("missing --public-key")
	}

	valid, err := teesks.VerifyMessage(*message, *signature, *publicKey)
	if err != nil {
		return err
	}
	return writeJSON(stdout, VerifyOutput{Valid: valid})
}

func requireLabelTag(label, tag string) error {
	if label == "" {
		return errors.New("missing --label")
	}
	if tag == "" {
		return errors.New("missing --tag")
	}
	return nil
}

func writeJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func usageError(message string) error {
	return fmt.Errorf("%s\nusage:\n  tee-sks check\n  tee-sks create --label <label> --tag <tag>\n  tee-sks sign --label <label> --tag <tag> --message <string>\n  tee-sks verify --message <string> --signature <base64> --public-key <base64>", message)
}
