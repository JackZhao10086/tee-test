//go:build darwin

package teeskscli

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFDataRef cf_data(const void *bytes, int len) {
	return CFDataCreate(kCFAllocatorDefault, bytes, len);
}

static int find_private_key_by_app_label(const unsigned char *appLabel, int appLabelLen, SecKeyRef *outKey) {
	CFDataRef cfAppLabel = cf_data(appLabel, appLabelLen);
	if (cfAppLabel == NULL) {
		return -2;
	}

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
	CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeRSA);
	CFDictionarySetValue(query, kSecAttrApplicationLabel, cfAppLabel);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

	CFTypeRef item = NULL;
	OSStatus status = SecItemCopyMatching(query, &item);
	CFRelease(query);
	CFRelease(cfAppLabel);
	if (status != errSecSuccess) {
		return (int)status;
	}

	*outKey = (SecKeyRef)item;
	return 0;
}

static int set_private_key_label(const unsigned char *appLabel, int appLabelLen, const char *label) {
	CFDataRef cfAppLabel = cf_data(appLabel, appLabelLen);
	CFStringRef cfLabel = CFStringCreateWithCString(kCFAllocatorDefault, label, kCFStringEncodingUTF8);
	if (cfAppLabel == NULL || cfLabel == NULL) {
		if (cfAppLabel != NULL) CFRelease(cfAppLabel);
		if (cfLabel != NULL) CFRelease(cfLabel);
		return -2;
	}

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(query, kSecClass, kSecClassKey);
	CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
	CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeRSA);
	CFDictionarySetValue(query, kSecAttrApplicationLabel, cfAppLabel);

	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
		kCFAllocatorDefault,
		0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(attrs, kSecAttrLabel, cfLabel);

	OSStatus status = SecItemUpdate(query, attrs);
	CFRelease(query);
	CFRelease(attrs);
	CFRelease(cfAppLabel);
	CFRelease(cfLabel);
	return (int)status;
}

static int sign_with_nonextractable_key(const unsigned char *appLabel, int appLabelLen, const unsigned char *digest, int digestLen, unsigned char **sigOut, long *sigLen) {
	SecKeyRef privateKey = NULL;
	int result = find_private_key_by_app_label(appLabel, appLabelLen, &privateKey);
	if (result != 0) {
		return result;
	}

	CFDataRef digestData = CFDataCreate(kCFAllocatorDefault, digest, digestLen);
	if (digestData == NULL) {
		CFRelease(privateKey);
		return -2;
	}

	CFErrorRef error = NULL;
	CFDataRef signature = SecKeyCreateSignature(
		privateKey,
		kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
		digestData,
		&error
	);
	CFRelease(digestData);
	if (signature == NULL) {
		CFRelease(privateKey);
		if (error != NULL) {
			int code = (int)CFErrorGetCode(error);
			CFRelease(error);
			return code;
		}
		return -1;
	}

	CFIndex len = CFDataGetLength(signature);
	unsigned char *sigBuf = malloc((size_t)len);
	if (sigBuf == NULL) {
		CFRelease(signature);
		CFRelease(privateKey);
		return -2;
	}
	memcpy(sigBuf, CFDataGetBytePtr(signature), (size_t)len);
	CFRelease(signature);
	*sigOut = sigBuf;
	*sigLen = len;

	CFRelease(privateKey);
	return 0;
}
*/
import "C"

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	sksattest "github.com/facebookincubator/sks/attest"

	"tee-test/internal/teesks"
)

func secureHardwareVendorData() (*sksattest.SecureHardwareVendorData, error) {
	return nil, fmt.Errorf("macOS backend uses Keychain non-extractable keys")
}

type darwinKeyMetadata struct {
	PublicKey string `json:"public_key"`
	AppLabel  string `json:"app_label"`
}

func createKey(label, tag string) (*keyResult, error) {
	metadataPath, err := darwinMetadataPath(label, tag)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(metadataPath); err == nil {
		return nil, fmt.Errorf("key metadata already exists for label %q and tag %q", label, tag)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	publicPKCS1 := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	appLabel := sha1.Sum(publicPKCS1)

	privateKeyFile, err := os.CreateTemp("", "tee-test-key-*.pem")
	if err != nil {
		return nil, fmt.Errorf("create temporary private key file: %w", err)
	}
	privateKeyPath := privateKeyFile.Name()
	defer os.Remove(privateKeyPath)
	if err := privateKeyFile.Chmod(0600); err != nil {
		privateKeyFile.Close()
		return nil, fmt.Errorf("chmod temporary private key file: %w", err)
	}
	if err := pem.Encode(privateKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		privateKeyFile.Close()
		return nil, fmt.Errorf("write temporary private key file: %w", err)
	}
	if err := privateKeyFile.Close(); err != nil {
		return nil, fmt.Errorf("close temporary private key file: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve current executable: %w", err)
	}
	defaultKeychain, err := defaultKeychainPath()
	if err != nil {
		return nil, err
	}
	importCmd := exec.Command("security", "import", privateKeyPath, "-k", defaultKeychain, "-t", "priv", "-f", "openssl", "-x", "-T", executable)
	if output, err := importCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("import non-extractable key: %w: %s", err, string(output))
	}
	if err := ensureDarwinKeyImported(appLabel[:]); err != nil {
		return nil, err
	}
	if err := setDarwinKeyLabel(appLabel[:], label); err != nil {
		return nil, err
	}

	encodedPublicKey, err := teesks.EncodePublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	metadata := darwinKeyMetadata{
		PublicKey: encodedPublicKey,
		AppLabel:  hex.EncodeToString(appLabel[:]),
	}
	if err := writeDarwinMetadata(metadataPath, metadata); err != nil {
		return nil, err
	}

	return &keyResult{PublicKey: &privateKey.PublicKey}, nil
}

func lookupKey(label, tag string) (*keyLookupResult, error) {
	metadata, err := readDarwinMetadata(label, tag)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &keyLookupResult{Exists: false}, nil
		}
		return nil, err
	}

	appLabel, err := hex.DecodeString(metadata.AppLabel)
	if err != nil {
		return nil, fmt.Errorf("decode key metadata app label: %w", err)
	}
	if err := ensureDarwinKeyImported(appLabel); err != nil {
		return &keyLookupResult{
			Exists: false,
			Note:   err.Error(),
		}, nil
	}

	publicKey, err := teesks.DecodePublicKey(metadata.PublicKey)
	if err != nil {
		return nil, err
	}
	return &keyLookupResult{
		Exists:    true,
		PublicKey: publicKey,
	}, nil
}

func signWithKey(label, tag, message string) (*signResult, error) {
	metadata, err := readDarwinMetadata(label, tag)
	if err != nil {
		return nil, err
	}
	appLabel, err := hex.DecodeString(metadata.AppLabel)
	if err != nil {
		return nil, fmt.Errorf("decode key metadata app label: %w", err)
	}
	publicKey, err := teesks.DecodePublicKey(metadata.PublicKey)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(message))
	var sig *C.uchar
	var sigLen C.long
	status := C.sign_with_nonextractable_key(
		(*C.uchar)(unsafe.Pointer(&appLabel[0])),
		C.int(len(appLabel)),
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.int(len(digest)),
		&sig,
		&sigLen,
	)
	if status != 0 {
		return nil, keychainError("sign with non-extractable key", int(status))
	}
	defer C.free(unsafe.Pointer(sig))

	return &signResult{
		Signature: C.GoBytes(unsafe.Pointer(sig), C.int(sigLen)),
		PublicKey: publicKey,
	}, nil
}

func readDarwinMetadata(label, tag string) (*darwinKeyMetadata, error) {
	metadataPath, err := darwinMetadataPath(label, tag)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("read key metadata: %w", err)
	}
	var metadata darwinKeyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("parse key metadata: %w", err)
	}
	return &metadata, nil
}

func writeDarwinMetadata(path string, metadata darwinKeyMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create key metadata directory: %w", err)
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode key metadata: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write key metadata: %w", err)
	}
	return nil
}

func ensureDarwinKeyImported(appLabel []byte) error {
	var key C.SecKeyRef
	status := C.find_private_key_by_app_label(
		(*C.uchar)(unsafe.Pointer(&appLabel[0])),
		C.int(len(appLabel)),
		&key,
	)
	if status != 0 {
		return keychainError("verify imported non-extractable key", int(status))
	}
	C.CFRelease(C.CFTypeRef(key))
	return nil
}

func setDarwinKeyLabel(appLabel []byte, label string) error {
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))
	status := C.set_private_key_label(
		(*C.uchar)(unsafe.Pointer(&appLabel[0])),
		C.int(len(appLabel)),
		cLabel,
	)
	if status != 0 {
		return keychainError("set keychain key label", int(status))
	}
	return nil
}

func defaultKeychainPath() (string, error) {
	output, err := exec.Command("security", "default-keychain").Output()
	if err != nil {
		return "", fmt.Errorf("resolve default keychain: %w", err)
	}
	path := string(output)
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "\"")
	if path == "" {
		return "", fmt.Errorf("resolve default keychain: empty path")
	}
	return path, nil
}

func darwinMetadataPath(label, tag string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	keyID := sha256.Sum256([]byte(label + "\x00" + tag))
	return filepath.Join(configDir, "tee-test", "keys", hex.EncodeToString(keyID[:])+".json"), nil
}

func keychainError(operation string, status int) error {
	switch status {
	case -25299:
		return fmt.Errorf("%s: key already exists", operation)
	case -25300:
		return fmt.Errorf("%s: key not found", operation)
	case -2:
		return fmt.Errorf("%s: allocation failed", operation)
	default:
		return fmt.Errorf("%s: Security framework status %d", operation, status)
	}
}
