// SPDX-License-Identifier: BSD-3-Clause

package sshcert

// The oracle: OpenSSH's ssh-keygen. It writes certificates carrying the
// extension with -O "extension:NAME=VALUE", and prints, with -L, the data
// field of an extension it does not know as hex. Neither depends on this
// package's reading of the specification.

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// sshKeygen returns the path of ssh-keygen. When it is missing the test
// fails if SSHCERT_REQUIRE_SSHKEYGEN=1, as it is on the CI lanes that must
// be judged, and is skipped otherwise.
func sshKeygen(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the ssh-keygen oracle runs on the linux and darwin lanes")
	}
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("SSHCERT_REQUIRE_SSHKEYGEN") == "1" {
			t.Fatalf("ssh-keygen is required on this lane (SSHCERT_REQUIRE_SSHKEYGEN=1) and is missing: %v", err)
		}
		t.Skipf("ssh-keygen not found (%v); set SSHCERT_REQUIRE_SSHKEYGEN=1 to make this a failure", err)
	}
	if out, err := exec.Command("ssh", "-V").CombinedOutput(); err == nil {
		t.Logf("oracle: %s", strings.TrimSpace(string(out)))
	}
	return p
}

func keygen(t *testing.T, bin, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen %q: %v\n%s", args, err, out)
	}
	return string(out)
}

// unknownOption is how ssh-keygen -L lists an extension it does not know:
// "NAME UNKNOWN OPTION: HEX (len N)".
var unknownOption = regexp.MustCompile(regexp.QuoteMeta(DomainGrantExtension) + ` UNKNOWN OPTION: ([0-9a-f]*) \(len (\d+)\)`)

// TestOracleSshKeygenReadsWhatWeWrite: ssh-keygen -L, given a certificate
// signed here, prints as the extension's data the specification's vector.
func TestOracleSshKeygenReadsWhatWeWrite(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()
	ca := testSigner(t)
	for i, v := range specVectors {
		val, err := EncodeDomainGrant(v.patterns)
		if err != nil {
			t.Fatal(err)
		}
		c := signedCert(t, ca, map[string]string{DomainGrantExtension: val, "permit-pty": ""})
		f := fmt.Sprintf("c%d-cert.pub", i)
		if err := os.WriteFile(filepath.Join(dir, f), ssh.MarshalAuthorizedKey(c), 0o600); err != nil {
			t.Fatal(err)
		}
		out := keygen(t, bin, dir, "-L", "-f", f)
		m := unknownOption.FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("%s: ssh-keygen -L does not list the extension:\n%s", v.name, out)
		}
		if m[1] != v.hex || m[2] != fmt.Sprint(len(v.hex)/2) {
			t.Errorf("%s: ssh-keygen -L reads %s (len %s), the spec says %s", v.name, m[1], m[2], v.hex)
		}
		if !strings.Contains(out, "permit-pty") {
			t.Errorf("%s: the other extension is lost:\n%s", v.name, out)
		}
	}
}

// TestOracleWeReadWhatSshKeygenWrites: a certificate signed by
// ssh-keygen -O "extension:NAME=VALUE" carries the same bytes as ours for
// the same patterns, and DomainGrant returns them.
func TestOracleWeReadWhatSshKeygenWrites(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()
	keygen(t, bin, dir, "-q", "-t", "ed25519", "-N", "", "-f", "ca")
	keygen(t, bin, dir, "-q", "-t", "ed25519", "-N", "", "-f", "user")
	ours := testSigner(t)
	for _, v := range specVectors {
		val, _ := EncodeDomainGrant(v.patterns)
		keygen(t, bin, dir, "-q", "-s", "ca", "-I", "id", "-n", "abc@myaccessid.org", "-V", "+1h",
			"-O", "clear", "-O", "extension:"+DomainGrantExtension+"="+val, "user.pub")
		c := readCert(t, filepath.Join(dir, "user-cert.pub"))
		got, present, err := DomainGrant(c)
		if err != nil || !present || !slices.Equal(got, v.patterns) {
			t.Errorf("%s: DomainGrant = %q %v %v", v.name, got, present, err)
		}
		raw := rawExtensions(t, c.Marshal())[DomainGrantExtension]
		if hex.EncodeToString(raw) != v.hex {
			t.Errorf("%s: ssh-keygen wrote %x, the spec says %s", v.name, raw, v.hex)
		}
		mine := rawExtensions(t, signedCert(t, ours, map[string]string{DomainGrantExtension: val}).Marshal())[DomainGrantExtension]
		if string(mine) != string(raw) {
			t.Errorf("%s: ssh-keygen wrote %x, this package %x", v.name, raw, mine)
		}
	}
	// What ssh-keygen lets an issuer write and the strict parser refuses:
	// present, and an error -- never read as absent.
	for _, val := range []string{`["a.example.org", "b.example.org"]`, `null`, `{"a":1}`, `["*"]`, `[]x`} {
		keygen(t, bin, dir, "-q", "-s", "ca", "-I", "id", "-n", "abc@myaccessid.org", "-V", "+1h",
			"-O", "clear", "-O", "extension:"+DomainGrantExtension+"="+val, "user.pub")
		c := readCert(t, filepath.Join(dir, "user-cert.pub"))
		if got, present, err := DomainGrant(c); !present || err == nil {
			t.Errorf("%s: DomainGrant = %q %v %v, want present and an error", val, got, present, err)
		}
	}
	// The name as a flag, with no data at all.
	keygen(t, bin, dir, "-q", "-s", "ca", "-I", "id", "-n", "abc@myaccessid.org", "-V", "+1h",
		"-O", "clear", "-O", "extension:"+DomainGrantExtension, "user.pub")
	c := readCert(t, filepath.Join(dir, "user-cert.pub"))
	if raw := rawExtensions(t, c.Marshal())[DomainGrantExtension]; len(raw) != 0 {
		t.Fatalf("a flag extension has data %x", raw)
	}
	if got, present, err := DomainGrant(c); !present || err == nil {
		t.Errorf("flag: DomainGrant = %q %v %v, want present and an error", got, present, err)
	}
}

func readCert(t *testing.T, path string) *ssh.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s is not a certificate", path)
	}
	return c
}
