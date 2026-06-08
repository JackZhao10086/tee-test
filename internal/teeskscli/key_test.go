package teeskscli

import "testing"

func TestCheckSupportReportsDarwinKeychainBackend(t *testing.T) {
	output := CheckSupport("darwin", nil)

	if !output.Supported {
		t.Fatal("expected darwin keychain backend to be supported")
	}
	if output.Status != "supported" {
		t.Fatalf("status = %q, want supported", output.Status)
	}
	if output.Backend != "keychain" {
		t.Fatalf("backend = %q, want keychain", output.Backend)
	}
}
