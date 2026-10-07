// SPDX-License-Identifier: BSD-3-Clause

package sshcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

// specVectors are the examples and test vectors of GÉANT's
// docs/ssh-domain-grant-ext.md, copied verbatim: the hex is the
// extension's data field, "string <json-array>".
var specVectors = []struct {
	name     string
	patterns []string
	hex      string
}{
	{"example 1", []string{"test.example.com"},
		"000000145b22746573742e6578616d706c652e636f6d225d"},
	{"example 2", []string{"test.example.com", "test.org"},
		"0000001f5b22746573742e6578616d706c652e636f6d222c22746573742e6f7267225d"},
	{"example 3", []string{"*.example.com"},
		"000000115b222a2e6578616d706c652e636f6d225d"},
	{"test vector 1", []string{},
		"000000025b5d"},
	{"test vector 2", []string{"*.prod.example.com", "*.staging.example.com", "ci.example.com"},
		"0000003f5b222a2e70726f642e6578616d706c652e636f6d222c222a2e73746167696e672e6578616d706c652e636f6d222c2263692e6578616d706c652e636f6d225d"},
}

// testSigner returns a fresh Ed25519 signer.
func testSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signedCert returns a user certificate for a fresh key, signed by ca,
// with extensions exts.
func signedCert(t testing.TB, ca ssh.Signer, exts map[string]string) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key:             testSigner(t).PublicKey(),
		Serial:          7,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"abc123@myaccessid.org"},
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions:     ssh.Permissions{Extensions: exts},
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

// rawExtensions walks the wire form of an Ed25519 user certificate
// (PROTOCOL.certkeys) and returns each extension's data field as it is on
// the wire, before any parser has unwrapped it.
func rawExtensions(t testing.TB, blob []byte) map[string][]byte {
	t.Helper()
	str := func() []byte {
		if len(blob) < 4 {
			t.Fatal("short certificate")
		}
		n := binary.BigEndian.Uint32(blob)
		if uint32(len(blob)-4) < n {
			t.Fatal("short certificate string")
		}
		s := blob[4 : 4+n]
		blob = blob[4+n:]
		return s
	}
	skip := func(n int) { blob = blob[n:] }
	if string(str()) != ssh.CertAlgoED25519v01 {
		t.Fatal("not an ed25519 certificate")
	}
	str()   // nonce
	str()   // public key
	skip(8) // serial
	skip(4) // type
	str()   // key id
	str()   // principals
	skip(16)
	str() // critical options
	exts := str()
	out := map[string][]byte{}
	blob, rest := exts, blob
	for len(blob) > 0 {
		k := string(str())
		out[k] = str()
	}
	blob = rest
	return out
}

// TestWireMatchesTheSpecificationsVectors: a certificate signed with the
// value EncodeDomainGrant returns carries, in its data field, the
// specification's test vector byte for byte; and parsing it back returns
// the patterns. This is what proves that golang.org/x/crypto/ssh wraps a
// non-empty extension value in one more SSH string: the value is the bare
// JSON, the wire has its length in front.
func TestWireMatchesTheSpecificationsVectors(t *testing.T) {
	ca := testSigner(t)
	for _, v := range specVectors {
		t.Run(v.name, func(t *testing.T) {
			val, err := EncodeDomainGrant(v.patterns)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := hex.DecodeString(v.hex)
			if val != string(want[4:]) {
				t.Fatalf("value %q, want the vector's JSON %q", val, want[4:])
			}
			c := signedCert(t, ca, map[string]string{DomainGrantExtension: val, "permit-pty": ""})
			raw := rawExtensions(t, c.Marshal())
			if got := hex.EncodeToString(raw[DomainGrantExtension]); got != v.hex {
				t.Fatalf("wire %s\nwant %s", got, v.hex)
			}
			if len(raw["permit-pty"]) != 0 {
				t.Fatalf("a flag extension has data %x", raw["permit-pty"])
			}
			pk, err := ssh.ParsePublicKey(c.Marshal())
			if err != nil {
				t.Fatal(err)
			}
			got, present, err := DomainGrant(pk.(*ssh.Certificate))
			if err != nil || !present || !slices.Equal(got, v.patterns) {
				t.Fatalf("read back %q %v %v, want %q", got, present, err, v.patterns)
			}
		})
	}
}

// TestWireWithoutTheInnerStringIsRefused: a CA that put the bare JSON in
// the data field, without the inner length the specification requires,
// makes a certificate golang.org/x/crypto/ssh refuses to parse at all,
// so sshcert-authorize, which parses with it, refuses it too.
func TestWireWithoutTheInnerStringIsRefused(t *testing.T) {
	ca := testSigner(t)
	c := signedCert(t, ca, map[string]string{DomainGrantExtension: `["a.example.org"]`})
	blob := c.Marshal()
	raw := rawExtensions(t, blob)[DomainGrantExtension]
	// Replace "string(string(json))" by "string(json)" in place: same
	// total length minus four, which the outer lengths must follow, so
	// rebuild the certificate's extension section by hand instead.
	inner := raw[4:]
	var exts []byte
	exts = binary.BigEndian.AppendUint32(exts, uint32(len(DomainGrantExtension)))
	exts = append(exts, DomainGrantExtension...)
	exts = binary.BigEndian.AppendUint32(exts, uint32(len(inner)))
	exts = append(exts, inner...)
	_, err := ssh.ParsePublicKey(replaceExtensions(t, blob, exts))
	if err == nil {
		t.Fatal("x/crypto/ssh parsed an extension value with no inner string")
	}
	t.Logf("x/crypto/ssh: %v", err)
}

// replaceExtensions returns blob with its extensions section replaced by
// exts (signature left as is: parsing does not verify it).
func replaceExtensions(t testing.TB, blob, exts []byte) []byte {
	t.Helper()
	off := 0
	str := func() {
		n := int(binary.BigEndian.Uint32(blob[off:]))
		off += 4 + n
	}
	str()
	str()
	str()
	off += 12
	str()
	str()
	off += 16
	str()
	start := off
	str()
	var out []byte
	out = append(out, blob[:start]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(exts)))
	out = append(out, exts...)
	return append(out, blob[off:]...)
}
