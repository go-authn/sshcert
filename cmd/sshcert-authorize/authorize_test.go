// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/sshcert"
	"golang.org/x/crypto/ssh"
)

const (
	host      = "login.example.org"
	principal = "abc123@myaccessid.org"
)

func signer(t testing.TB) ssh.Signer {
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

// cert signs a user certificate with ca; grant == nil leaves the extension
// out, otherwise it is stored verbatim.
func cert(t testing.TB, ca ssh.Signer, serial uint64, grant *string) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key:             signer(t).PublicKey(),
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           "id with space",
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if grant != nil {
		c.Permissions.Extensions[sshcert.DomainGrantExtension] = *grant
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func blob(c ssh.PublicKey) string { return base64.StdEncoding.EncodeToString(c.Marshal()) }

func ptr(s string) *string { return &s }

type env struct {
	t   *testing.T
	ca  ssh.Signer
	dir string
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, ca: signer(t), dir: t.TempDir()}
	os.MkdirAll(e.at("principals"), 0o755)
	e.write("principals/alice", "# the CUIDs that may log in as alice\n\n"+principal+"\nother@myaccessid.org\n")
	return e
}

func (e *env) at(n string) string { return filepath.Join(e.dir, n) }

func (e *env) write(n, s string) {
	e.t.Helper()
	if err := os.WriteFile(e.at(n), []byte(s), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// run runs the command with --syslog=false and the principals directory.
func (e *env) run(stdin string, args ...string) (code int, stdout, stderr string) {
	var o, er bytes.Buffer
	a := append([]string{"--syslog=false", "--principals-dir", e.at("principals")}, args...)
	code = run(a, strings.NewReader(stdin), &o, &er)
	return code, o.String(), er.String()
}

// expect checks a run: a refusal is exit 1 and nothing on stdout.
func (e *env) expect(name string, wantOK bool, wantLog string, stdin string, args ...string) {
	e.t.Helper()
	code, out, log := e.run(stdin, args...)
	if wantOK {
		if code != 0 || out != principal+"\nother@myaccessid.org\n" {
			e.t.Errorf("%s: exit %d, stdout %q, want the principals\n%s", name, code, out, log)
		}
	} else if code != 1 || out != "" {
		e.t.Errorf("%s: exit %d, stdout %q, want a refusal\n%s", name, code, out, log)
	}
	if !strings.Contains(log, wantLog) {
		e.t.Errorf("%s: log lacks %q:\n%s", name, wantLog, log)
	}
}

func TestDecisions(t *testing.T) {
	e := newEnv(t)
	d := []string{"--domain", host}
	granted := blob(cert(t, e.ca, 1, ptr(`["*.example.org"]`)))
	none := blob(cert(t, e.ca, 2, nil))
	e.expect("granted", true, `action=authorized user=alice cert_principals=["abc123@myaccessid.org"] server_principals=["abc123@myaccessid.org","other@myaccessid.org"] domain=login.example.org serial=1`, "", append(d, "alice", granted)...)
	e.expect("granted, logged as processed", true, `action=cert_processed serial=1 key_id="id with space" extension=ssh-domain-grant@core.aai.geant.org ca_fingerprint=SHA256:`, "", append(d, "alice", granted)...)
	e.expect("granted, case", true, "action=authorized", "", "--domain", "LOGIN.Example.ORG", "alice", granted)
	e.expect("another domain", false, `reason="domain not granted" grant=["*.example.com"]`, "", append(d, "alice", blob(cert(t, e.ca, 3, ptr(`["*.example.com"]`))))...)
	e.expect("an empty grant", false, `reason="domain not granted" grant=[]`, "", append(d, "alice", blob(cert(t, e.ca, 3, ptr(`[]`))))...)
	e.expect("no grant", false, `reason="no domain grant" serial=2`, "", append(d, "alice", none)...)
	e.expect("no grant, allowed", true, "action=no_grant_allowed user=alice", "", append([]string{"--allow-no-grant"}, append(d, "alice", none)...)...)
	for _, bad := range []string{`null`, `{}`, `[1]`, `["login.example.org"] `, `["*"]`, ``} {
		c := blob(cert(t, e.ca, 4, ptr(bad)))
		e.expect("malformed "+bad, false, `reason="malformed domain grant: sshcert: invalid domain grant`, "", append(d, "alice", c)...)
		e.expect("malformed, allow-no-grant "+bad, false, "malformed domain grant", "", append([]string{"--allow-no-grant"}, append(d, "alice", c)...)...)
	}
	// Another extension name, as GÉANT's --extension.
	other := cert(t, e.ca, 5, nil)
	other.Permissions.Extensions["grant@example.org"] = `["login.example.org"]`
	other.SignCert(rand.Reader, e.ca)
	e.expect("--extension", true, "extension=grant@example.org", "", append([]string{"--extension", "grant@example.org"}, append(d, "alice", blob(other))...)...)
	e.expect("--extension, default name", false, "no domain grant", "", append(d, "alice", blob(other))...)

	// The certificate, as sshd and people give it.
	c := cert(t, e.ca, 6, ptr(`["login.example.org"]`))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))) + " alice@laptop"
	e.expect("a -cert.pub line", true, "action=authorized", "", append(d, "alice", line)...)
	e.expect("on stdin", true, "action=authorized", blob(c)+"\n", append(d, "alice")...)
	e.expect("%t matches", true, "action=authorized", "", append(d, "alice", blob(c), ssh.CertAlgoED25519v01)...)
	e.expect("%t does not", false, "key type ssh-ed25519 is not the certificate's", "", append(d, "alice", blob(c), ssh.KeyAlgoED25519)...)
	e.expect("no certificate", false, `reason="no certificate"`, "", append(d, "alice")...)
	e.expect("not base64", false, "unreadable certificate", "", append(d, "alice", "!!!")...)
	e.expect("not a key", false, "unreadable certificate", "", append(d, "alice", "AAAA")...)
	e.expect("a bad line", false, "unreadable certificate", "", append(d, "alice", "ssh-ed25519 !!! x")...)
	e.expect("a plain key", false, "a ssh-ed25519 key, not a certificate", "", append(d, "alice", blob(e.ca.PublicKey()))...)
	hc := cert(t, e.ca, 7, ptr(`["login.example.org"]`))
	hc.CertType = ssh.HostCert
	hc.SignCert(rand.Reader, e.ca)
	e.expect("a host certificate", false, "not a user certificate", "", append(d, "alice", blob(hc))...)

	// Users and principals.
	for _, u := range []string{"", ".", "..", "../alice", `a\b`, "a\x00"} {
		e.expect("user "+u, false, "invalid user name", "", append(d, u, granted)...)
	}
	e.expect("no principals file", false, `reason="no principals file for the user"`, "", append(d, "bob", granted)...)
	e.write("principals/carol", "# nobody\n\n")
	e.expect("an empty principals file", false, `reason="no principals for the user"`, "", append(d, "carol", granted)...)
	os.Mkdir(e.at("principals/dave"), 0o755)
	e.expect("a principals directory", false, "action=error user=dave reason=\"reading the principals file", "", append(d, "dave", granted)...)
	e.write("principals/erin", strings.Repeat("x", maxInput+1))
	e.expect("a huge principals file", false, "larger than", "", append(d, "erin", granted)...)
	var o, er bytes.Buffer
	if code := run([]string{"--syslog=false", "--principals-dir", "", "--domain", host, "alice", granted}, nil, &o, &er); code != 1 || o.Len() != 0 ||
		!strings.Contains(er.String(), "no principals directory configured") {
		t.Errorf("no principals dir: %d %q %s", code, o.String(), er.String())
	}
}

func TestDomainSources(t *testing.T) {
	e := newEnv(t)
	granted := blob(cert(t, e.ca, 1, ptr(`["login.example.org"]`)))
	e.write("domain", "# this host\n\nlogin.example.org\n")
	e.expect("file", true, "domain=login.example.org", "", "--domain-file", e.at("domain"), "alice", granted)
	e.write("domains", "a.example.com\nlogin.example.org\n")
	e.expect("file, two names", true, "domain=a.example.com,login.example.org", "", "--domain-file", e.at("domains"), "alice", granted)
	e.write("other", "a.example.com\n")
	e.expect("file, another name", false, "domain not granted", "", "--domain-file", e.at("other"), "alice", granted)
	e.expect("--domain overrides the file", true, "action=authorized", "", "--domain", host, "--domain-file", e.at("other"), "alice", granted)
	t.Setenv("SSHCERT_TEST_DOMAIN", host)
	e.expect("env", true, "action=authorized", "", "--domain-env", "SSHCERT_TEST_DOMAIN", "--domain-file", e.at("other"), "alice", granted)
	t.Setenv("SSHCERT_TEST_DOMAIN", "")
	e.expect("env empty: the file", false, "domain not granted", "", "--domain-env", "SSHCERT_TEST_DOMAIN", "--domain-file", e.at("other"), "alice", granted)
	e.expect("missing file", false, `action=error reason="reading the domain file`, "", "--domain-file", e.at("nope"), "alice", granted)
	e.write("empty", "# nothing\n")
	e.expect("empty file", false, `reason="no domain configured for this host"`, "", "--domain-file", e.at("empty"), "alice", granted)
	e.expect("no source", false, "no domain configured", "", "--domain-file", "", "alice", granted)
	for _, bad := range []string{"*.example.org", "login..example.org", "login.example.org.", "login_1.example.org"} {
		e.expect("invalid "+bad, false, "is not a valid host name", "", "--domain", bad, "alice", granted)
	}
}

func TestKRL(t *testing.T) {
	e := newEnv(t)
	c := cert(t, e.ca, 42, ptr(`["login.example.org"]`))
	keep := cert(t, e.ca, 43, ptr(`["login.example.org"]`))
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	writeKRL := func(name string, expires time.Time, serials ...uint64) {
		b := krl.NewBuilder(1, "test")
		for _, s := range serials {
			b.RevokeSerial(e.ca.PublicKey(), s)
		}
		if !expires.IsZero() {
			b.SetExpires(expires)
		}
		raw, err := b.Marshal(t0)
		if err != nil {
			t.Fatal(err)
		}
		e.write(name, string(raw))
	}
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return t0.Add(time.Minute) }
	writeKRL("revoked.krl", t0.Add(time.Hour), 42)
	writeKRL("forever.krl", time.Time{}, 42)
	writeKRL("lapsed.krl", t0.Add(time.Minute), 1)
	d := []string{"--domain", host}
	e.expect("revoked", false, `reason="certificate revoked" serial=42`, "", append(d, "--krl", e.at("revoked.krl"), "alice", blob(c))...)
	e.expect("not revoked", true, "action=authorized", "", append(d, "--krl", e.at("revoked.krl"), "alice", blob(keep))...)
	e.expect("no expiry", false, "certificate revoked", "", append(d, "--krl", e.at("forever.krl"), "alice", blob(c))...)
	e.expect("no expiry, not revoked", true, "action=authorized", "", append(d, "--krl", e.at("forever.krl"), "alice", blob(keep))...)
	e.expect("expired", false, `reason="KRL expired at 2026-10-07T12:01:00Z"`, "", append(d, "--krl", e.at("lapsed.krl"), "alice", blob(keep))...)
	e.expect("missing", false, `reason="KRL unreadable: open`, "", append(d, "--krl", e.at("nope.krl"), "alice", blob(keep))...)
	e.write("junk.krl", "not a KRL")
	e.expect("invalid", false, `reason="KRL invalid:`, "", append(d, "--krl", e.at("junk.krl"), "alice", blob(keep))...)
	// The revocation is checked before the grant: a revoked certificate
	// with no grant is refused as revoked even with --allow-no-grant.
	nog := cert(t, e.ca, 42, nil)
	e.expect("revoked, no grant", false, "certificate revoked", "", append(d, "--allow-no-grant", "--krl", e.at("revoked.krl"), "alice", blob(nog))...)
}

func TestUsageAndFlags(t *testing.T) {
	e := newEnv(t)
	granted := blob(cert(t, e.ca, 1, ptr(`["login.example.org"]`)))
	for _, tc := range []struct {
		args []string
		code int
		out  string
		log  string
	}{
		{[]string{"--version"}, 0, "sshcert-authorize dev\n", ""},
		{[]string{"--help"}, 0, "", "usage: sshcert-authorize"},
		{[]string{"--nope"}, 2, "", "flag provided but not defined"},
		{[]string{"--domain", host}, 2, "", "usage: USER"},
		{[]string{"--domain", host, "alice", granted, ssh.CertAlgoED25519v01, "x"}, 2, "", "usage: USER"},
	} {
		code, out, log := e.run("", tc.args...)
		if code != tc.code || out != tc.out || !strings.Contains(log, tc.log) {
			t.Errorf("%q: exit %d stdout %q log %q", tc.args, code, out, log)
		}
	}
	var o, er bytes.Buffer
	code := run([]string{"--syslog=false", "--domain", host, "alice"}, errReader{}, &o, &er)
	if code != 1 || !strings.Contains(er.String(), "reading the certificate from stdin: broken") {
		t.Errorf("stdin error: %d %s", code, er.String())
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken") }

// fakeSyslog records what reaches syslog, by level.
type fakeSyslog struct {
	lines  []string
	closed bool
}

func (f *fakeSyslog) rec(l, m string) error { f.lines = append(f.lines, l+" "+m); return nil }
func (f *fakeSyslog) Debug(m string) error  { return f.rec("debug", m) }
func (f *fakeSyslog) Info(m string) error   { return f.rec("info", m) }
func (f *fakeSyslog) Warning(m string) error {
	return f.rec("warning", m)
}
func (f *fakeSyslog) Err(m string) error { return f.rec("err", m) }
func (f *fakeSyslog) Close() error       { f.closed = true; return nil }

func TestSyslog(t *testing.T) {
	e := newEnv(t)
	granted := blob(cert(t, e.ca, 1, ptr(`["login.example.org"]`)))
	defer func(f func(string) (syslogWriter, error)) { dialSyslog = f }(dialSyslog)
	fs := &fakeSyslog{}
	dialSyslog = func(tag string) (syslogWriter, error) {
		if tag != "sshcert-authorize" {
			t.Errorf("tag %q", tag)
		}
		return fs, nil
	}
	pd := e.at("principals")
	var o, er bytes.Buffer
	if code := run([]string{"--principals-dir", pd, "--domain", host, "alice", granted}, nil, &o, &er); code != 0 || er.Len() != 0 {
		t.Fatalf("exit %d, stderr %q (syslog is the only log without --debug)", code, er.String())
	}
	run([]string{"--principals-dir", pd, "--domain", "other.example.org", "alice", granted}, nil, &o, &er)
	run([]string{"--principals-dir", pd, "--domain", "bad..name", "alice", granted}, nil, &o, &er)
	run([]string{"--debug", "--principals-dir", pd, "--domain", host, "alice", granted}, nil, &o, &er)
	all := strings.Join(fs.lines, "\n")
	for _, want := range []string{"info action=cert_processed", "info action=authorized", "warning action=denied", "err action=error", "debug granted by"} {
		if !strings.Contains(all, want) {
			t.Errorf("syslog lacks %q:\n%s", want, all)
		}
	}
	if !fs.closed {
		t.Error("syslog not closed")
	}
	if !strings.Contains(er.String(), "DEBUG: granted by") || !strings.Contains(er.String(), "INFO: action=authorized") {
		t.Errorf("--debug does not mirror to stderr: %q", er.String())
	}
	dialSyslog = func(string) (syslogWriter, error) { return nil, errors.New("no syslog here") }
	o.Reset()
	er.Reset()
	if code := run([]string{"--principals-dir", pd, "--domain", host, "alice", granted}, nil, &o, &er); code != 1 || o.Len() != 0 ||
		!strings.Contains(er.String(), "syslog: no syslog here") {
		t.Errorf("syslog unavailable: exit %d stdout %q stderr %q", code, o.String(), er.String())
	}
}

// TestRealSyslog opens the platform's syslog once. Whether it is there
// depends on the machine; either way nothing is written to it.
func TestRealSyslog(t *testing.T) {
	w, err := realDialSyslog("sshcert-authorize-test")
	if err != nil {
		t.Logf("no syslog here: %v", err)
		return
	}
	w.Close()
}

var realDialSyslog = dialSyslog

func TestMain(t *testing.T) {
	defer func(f func(int), a []string) { exit, os.Args = f, a }(exit, os.Args)
	got := -1
	exit = func(c int) { got = c }
	os.Args = []string{"sshcert-authorize", "--version"}
	stdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	main()
	os.Stdout = stdout
	w.Close()
	var b bytes.Buffer
	b.ReadFrom(r)
	if got != 0 || b.String() != "sshcert-authorize dev\n" {
		t.Errorf("main: exit %d, %q", got, b.String())
	}
}

func TestKV(t *testing.T) {
	for in, want := range map[string]string{
		"":                  `""`,
		"alice":             "alice",
		"SHA256:ab+/c":      "SHA256:ab+/c",
		`["a","b"]`:         `["a","b"]`,
		"a b":               `"a b"`,
		"a=b":               `"a=b"`,
		"a\nb":              `"a\nb"`,
		`a"b`:               `"a\"b"`,
		`a\b`:               `"a\\b"`,
		"é":                 `"\u00e9"`,
		"x action=accepted": `"x action=accepted"`,
	} {
		if got := kv(in); got != want {
			t.Errorf("kv(%q) = %s, want %s", in, got, want)
		}
	}
}
