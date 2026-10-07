// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/sshcert"
	"golang.org/x/crypto/ssh"
)

// The live judge: real sshds, run as the test's own user on loopback
// ports, with TrustedUserCAKeys naming two CAs and AuthorizedPrincipalsCommand
// naming this command (in three configurations) or GÉANT's
// ssh-cert-authorize, and real ssh logins.
//
// sshd runs an AuthorizedPrincipalsCommand only from a path every
// component of which is owned by root and writable by no one else, so the
// binaries must be installed: SSHCERT_AUTHORIZE (this command) and
// SSHCERT_GEANT_AUTHORIZE (GÉANT's, built by testdata/geantjudge/build.sh)
// name them. Without them, or without sshd, ssh and ssh-keygen, the test
// is skipped -- unless SSHCERT_REQUIRE_SSHD=1 (the linux CI lane), where
// that is a failure.
//
// The two CAs stand for a federation's CA, which grants domains, and a
// second CA the site also trusts (its own, or another federation's),
// which does not: the multi-CA scenario of the README.
func TestSSHDJudges(t *testing.T) {
	need := func(what string, err error) {
		t.Helper()
		if err == nil {
			return
		}
		if os.Getenv("SSHCERT_REQUIRE_SSHD") == "1" {
			t.Fatalf("%s is required on this lane (SSHCERT_REQUIRE_SSHD=1): %v", what, err)
		}
		t.Skipf("%s: %v", what, err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("sshd is not run on Windows here")
	}
	sshd, err := lookSSHD()
	need("sshd", err)
	sshBin, err := exec.LookPath("ssh")
	need("ssh", err)
	keygen, err := exec.LookPath("ssh-keygen")
	need("ssh-keygen", err)
	ours, err := installed("SSHCERT_AUTHORIZE")
	need("sshcert-authorize, installed", err)
	geant, err := installed("SSHCERT_GEANT_AUTHORIZE")
	need("GÉANT's ssh-cert-authorize, installed", err)
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sshBin, "-V").CombinedOutput(); err == nil {
		t.Logf("judge: %s", strings.TrimSpace(string(out)))
	}

	// A short path: sshd and ssh are fussy about long ones.
	dir, err := os.MkdirTemp("", "sshcert-sshd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	at := func(n string) string { return filepath.Join(dir, n) }
	kg := func(args ...string) {
		t.Helper()
		cmd := exec.Command(keygen, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %q: %v\n%s", args, err, out)
		}
	}
	for _, k := range []string{"host", "fedca", "siteca"} {
		kg("-q", "-t", "ed25519", "-N", "", "-f", k)
	}
	cas, _ := os.ReadFile(at("fedca.pub"))
	site, _ := os.ReadFile(at("siteca.pub"))
	os.WriteFile(at("trusted_cas"), append(cas, site...), 0o644)
	os.MkdirAll(at("principals"), 0o755)
	os.WriteFile(at("principals/"+me.Username), []byte(principal+"\n"), 0o644)

	const domain = "login.sshcert.test"
	// Certificates signed by ssh-keygen: -O extension:NAME=VALUE.
	byKeygen := func(name, ca, value string) {
		kg("-q", "-t", "ed25519", "-N", "", "-f", name)
		args := []string{"-q", "-s", ca, "-I", name, "-n", principal, "-V", "-5m:+1h", "-z", "1"}
		if value != "" {
			args = append(args, "-O", "extension:"+sshcert.DomainGrantExtension+"="+value)
		}
		kg(append(args, name+".pub")...)
	}
	byKeygen("kg-granted", "fedca", `["*.sshcert.test"]`)
	byKeygen("kg-elsewhere", "fedca", `["*.example.org"]`)
	byKeygen("kg-null", "fedca", `null`)
	byKeygen("kg-empty", "fedca", `[]`)
	byKeygen("kg-nogrant-fed", "fedca", "")
	byKeygen("kg-nogrant-site", "siteca", "")
	// Certificates signed by this package.
	caPriv, _ := os.ReadFile(at("fedca"))
	fedCA, err := ssh.ParsePrivateKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	byLib := func(name string, serial uint64, patterns []string) {
		kg("-q", "-t", "ed25519", "-N", "", "-f", name)
		pub, _ := os.ReadFile(at(name + ".pub"))
		k, _, _, _, err := ssh.ParseAuthorizedKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		c := &ssh.Certificate{
			Key: k, Serial: serial, CertType: ssh.UserCert, KeyId: name,
			ValidPrincipals: []string{principal},
			ValidAfter:      uint64(time.Now().Add(-5 * time.Minute).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		}
		if err := sshcert.SetDomainGrant(c, patterns); err != nil {
			t.Fatal(err)
		}
		if err := c.SignCert(rand.Reader, fedCA); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(at(name+"-cert.pub"), ssh.MarshalAuthorizedKey(c), 0o644)
	}
	byLib("lib-granted", 77, []string{"login.sshcert.test"})
	byLib("lib-elsewhere", 78, []string{"login.example.org"})
	// A KRL revoking lib-granted.
	b := krl.NewBuilder(1, "sshd judge")
	b.RevokeSerial(fedCA.PublicKey(), 77)
	b.SetExpires(time.Now().Add(time.Hour))
	raw, err := b.Marshal(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(at("revoked.krl"), raw, 0o644)

	common := fmt.Sprintf("--syslog=false --domain %s --principals-dir %s", domain, at("principals"))
	servers := []struct{ name, command string }{
		{"ours", ours + " " + common + " %u %k"},
		{"ours --allow-no-grant", ours + " --allow-no-grant " + common + " %u %k"},
		{"ours --krl", ours + " --krl " + at("revoked.krl") + " " + common + " %u %k"},
		{"GÉANT", geant + " " + common + " %u %k"},
	}
	// in[i] is whether the certificate logs in on servers[i].
	certs := []struct {
		name string
		in   [4]bool
		why  string
	}{
		{"kg-granted", [4]bool{true, true, true, true}, "granted for the host's domain"},
		{"lib-granted", [4]bool{true, true, false, true}, "granted, signed by this package; revoked by the KRL"},
		{"kg-elsewhere", [4]bool{false, false, false, false}, "granted for another domain"},
		{"lib-elsewhere", [4]bool{false, false, false, false}, "granted for another host, signed by this package"},
		{"kg-nogrant-site", [4]bool{false, true, false, true}, "no grant, from the second CA: GÉANT's fail-open"},
		{"kg-nogrant-fed", [4]bool{false, true, false, true}, "no grant, from the federation's CA"},
		{"kg-null", [4]bool{false, false, false, true}, "grant `null`: GÉANT reads no domains, and lets it in"},
		{"kg-empty", [4]bool{false, false, false, true}, "grant `[]`: GÉANT reads no domains, and lets it in"},
	}

	for i, s := range servers {
		port := freePort(t)
		cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
TrustedUserCAKeys %s
AuthorizedPrincipalsCommand %s
AuthorizedPrincipalsCommandUser %s
AuthorizedKeysFile none
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
UsePAM no
LogLevel DEBUG1
`, port, at("host"), at(fmt.Sprintf("sshd%d.pid", i)), at("trusted_cas"), s.command, me.Username)
		conf := at(fmt.Sprintf("sshd%d_config", i))
		os.WriteFile(conf, []byte(cfg), 0o644)
		if out, err := exec.Command(sshd, "-t", "-f", conf).CombinedOutput(); err != nil {
			t.Fatalf("%s: sshd -t: %v\n%s", s.name, err, out)
		}
		daemon := exec.Command(sshd, "-D", "-e", "-f", conf)
		logPath := at(fmt.Sprintf("sshd%d.log", i))
		logf, _ := os.Create(logPath)
		daemon.Stderr = logf
		if err := daemon.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { daemon.Process.Kill(); daemon.Wait(); logf.Close() })
		waitPort(t, port)
		for _, c := range certs {
			got := exec.Command(sshBin, "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
				"-i", at(c.name), "-o", "CertificateFile="+at(c.name+"-cert.pub"),
				"-p", fmt.Sprint(port), "-l", me.Username, "127.0.0.1", "true").Run() == nil
			verdict := map[bool]string{true: "logs in", false: "refused"}
			t.Logf("%-22s %-16s %-8s (%s)", s.name, c.name, verdict[got], c.why)
			if got != c.in[i] {
				log, _ := os.ReadFile(logPath)
				t.Errorf("%s, %s (%s): %s, want %s\nsshd:\n%s", s.name, c.name, c.why, verdict[got], verdict[c.in[i]], tail(string(log), 40))
			}
		}
	}
}

// installed returns the absolute path an environment variable names. sshd
// itself judges whether it is safe to run (see the test's comment).
func installed(env string) (string, error) {
	p := os.Getenv(env)
	if p == "" {
		return "", fmt.Errorf("%s is not set", env)
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s=%s is not an absolute path", env, p)
	}
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

func tail(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func lookSSHD() (string, error) {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sshd never listened")
}
