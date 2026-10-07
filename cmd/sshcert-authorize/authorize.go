// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/sshcert"
	"golang.org/x/crypto/ssh"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

// now is the clock, replaced by the tests.
var now = time.Now

// maxInput bounds what is read from stdin and from the files the command
// is given.
const maxInput = 1 << 20

type config struct {
	extension     string
	domainFile    string
	domainEnv     string
	domain        string
	principalsDir string
	krlFile       string
	allowNoGrant  bool
}

// run is the command; it returns the exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var c config
	fl := flag.NewFlagSet("sshcert-authorize", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.StringVar(&c.extension, "extension", sshcert.DomainGrantExtension, "name of the domain-grant extension")
	fl.StringVar(&c.domainFile, "domain-file", "/etc/ssh/cert-allowed-domain.conf", "file holding the host's domain, one name per line")
	fl.StringVar(&c.domainEnv, "domain-env", "", "environment variable holding the host's domain")
	fl.StringVar(&c.domain, "domain", "", "the host's domain (overrides --domain-env and --domain-file)")
	fl.StringVar(&c.principalsDir, "principals-dir", "/etc/ssh/auth_principals", "directory of principals files, one per user")
	fl.StringVar(&c.krlFile, "krl", "", "refuse certificates this OpenSSH KRL revokes, and every certificate once it has expired or cannot be read")
	fl.BoolVar(&c.allowNoGrant, "allow-no-grant", false, "let in a certificate with no domain grant (GÉANT's behaviour); a malformed grant is still refused")
	useSyslog := fl.Bool("syslog", true, "log to syslog, facility AUTH (--syslog=false: to stderr)")
	debug := fl.Bool("debug", false, "log details")
	showVersion := fl.Bool("version", false, "print the version and exit")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: sshcert-authorize [flags] USER [CERTIFICATE [KEYTYPE]]\n\n"+
			"An sshd AuthorizedPrincipalsCommand (%%u %%k) that refuses a certificate whose\n"+
			"%s extension does not grant this host, or that has none.\n\n", sshcert.DomainGrantExtension)
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "sshcert-authorize %s\n", version)
		return 0
	}
	lg, err := newLogger(*useSyslog, *debug, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "sshcert-authorize: %v\n", err)
		return 1
	}
	defer lg.close()
	if fl.NArg() < 1 || fl.NArg() > 3 {
		lg.errorf("action=error reason=%s", kv("usage: USER [CERTIFICATE [KEYTYPE]]"))
		return 2
	}
	user := fl.Arg(0)
	var blob string
	if fl.NArg() > 1 {
		blob = fl.Arg(1)
	} else {
		b, err := io.ReadAll(io.LimitReader(stdin, maxInput))
		if err != nil {
			lg.errorf("action=error reason=%s", kv("reading the certificate from stdin: "+err.Error()))
			return 1
		}
		blob = string(b)
	}
	principals, ok := authorize(&c, user, blob, fl.Arg(2), lg)
	if !ok {
		return 1
	}
	for _, p := range principals {
		fmt.Fprintln(stdout, p)
	}
	return 0
}

// authorize decides; it logs its decision, and returns the principals to
// print and true, or false for a refusal.
func authorize(c *config, user, blob, keyType string, lg *logger) ([]string, bool) {
	if err := checkUser(user); err != nil {
		lg.errorf("action=error user=%s reason=%s", kv(user), kv(err.Error()))
		return nil, false
	}
	domains, err := hostDomains(c)
	if err != nil {
		lg.errorf("action=error reason=%s", kv(err.Error()))
		return nil, false
	}
	domain := strings.Join(domains, ",")
	cert, err := parseCert(blob)
	if err != nil {
		lg.warningf("action=denied user=%s domain=%s reason=%s", kv(user), kv(domain), kv(err.Error()))
		return nil, false
	}
	caFP := ssh.FingerprintSHA256(cert.SignatureKey)
	lg.infof("action=cert_processed serial=%d key_id=%s extension=%s ca_fingerprint=%s",
		cert.Serial, kv(cert.KeyId), kv(c.extension), caFP)
	deny := func(reason string, more ...string) ([]string, bool) {
		lg.warningf("action=denied user=%s domain=%s reason=%s%s serial=%d ca_fingerprint=%s",
			kv(user), kv(domain), kv(reason), strings.Join(more, ""), cert.Serial, caFP)
		return nil, false
	}
	if keyType != "" && keyType != cert.Type() {
		return deny(fmt.Sprintf("key type %s is not the certificate's, %s", keyType, cert.Type()))
	}
	if c.krlFile != "" {
		if reason := revoked(c.krlFile, cert); reason != "" {
			return deny(reason)
		}
	}
	patterns, present, err := sshcert.DomainGrantNamed(cert, c.extension)
	switch {
	case err != nil:
		return deny("malformed domain grant: " + err.Error())
	case !present && !c.allowNoGrant:
		return deny("no domain grant")
	case !present:
		lg.warningf("action=no_grant_allowed user=%s domain=%s serial=%d ca_fingerprint=%s",
			kv(user), kv(domain), cert.Serial, caFP)
	default:
		granted := false
		for _, d := range domains {
			granted = granted || sshcert.Grants(patterns, d)
		}
		if !granted {
			return deny("domain not granted", " grant="+kv(jsonList(patterns)))
		}
		lg.debugf("granted by %s", jsonList(patterns))
	}
	principals, reason, err := readPrincipals(c.principalsDir, user)
	if err != nil {
		lg.errorf("action=error user=%s reason=%s", kv(user), kv(err.Error()))
		return nil, false
	}
	if reason != "" {
		return deny(reason)
	}
	lg.infof("action=authorized user=%s cert_principals=%s server_principals=%s domain=%s serial=%d ca_fingerprint=%s",
		kv(user), kv(jsonList(cert.ValidPrincipals)), kv(jsonList(principals)), kv(domain), cert.Serial, caFP)
	return principals, true
}

// checkUser refuses a user name that would name another file in the
// principals directory. sshd only asks about accounts that exist, so this
// is a second line.
func checkUser(user string) error {
	if user == "" || user == "." || user == ".." || strings.ContainsAny(user, "/\\\x00") {
		return fmt.Errorf("invalid user name %q", user)
	}
	return nil
}

// hostDomains returns the host's names, from the first source configured.
func hostDomains(c *config) ([]string, error) {
	var names []string
	switch {
	case c.domain != "":
		names = []string{strings.TrimSpace(c.domain)}
	case c.domainEnv != "" && os.Getenv(c.domainEnv) != "":
		names = []string{strings.TrimSpace(os.Getenv(c.domainEnv))}
	case c.domainFile != "":
		b, err := readFile(c.domainFile)
		if err != nil {
			return nil, fmt.Errorf("reading the domain file: %w", err)
		}
		names = lines(string(b))
	}
	if len(names) == 0 {
		return nil, errors.New("no domain configured for this host")
	}
	for _, n := range names {
		// A host name is a pattern without wildcards.
		if strings.Contains(n, "*") || sshcert.ValidatePattern(n) != nil {
			return nil, fmt.Errorf("the configured domain %q is not a valid host name", n)
		}
	}
	return names, nil
}

// parseCert reads a certificate given as sshd's %k (base64) or as a line
// of an authorized_keys or -cert.pub file.
func parseCert(blob string) (*ssh.Certificate, error) {
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return nil, errors.New("no certificate")
	}
	var key ssh.PublicKey
	var err error
	if strings.ContainsAny(blob, " \t") {
		key, _, _, _, err = ssh.ParseAuthorizedKey([]byte(blob))
	} else {
		var raw []byte
		if raw, err = base64.StdEncoding.DecodeString(blob); err == nil {
			key, err = ssh.ParsePublicKey(raw)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("unreadable certificate: %v", err)
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("a %s key, not a certificate", key.Type())
	}
	if cert.CertType != ssh.UserCert {
		return nil, errors.New("not a user certificate")
	}
	return cert, nil
}

// revoked returns why the KRL refuses cert, or "". A list that cannot be
// read or has expired refuses every certificate: read as empty, it would
// let in what it was meant to keep out.
func revoked(path string, cert *ssh.Certificate) string {
	b, err := readFile(path)
	if err != nil {
		return "KRL unreadable: " + err.Error()
	}
	k, err := krl.Parse(b)
	if err != nil {
		return "KRL invalid: " + err.Error()
	}
	if !k.Expires.IsZero() && !now().Before(k.Expires) {
		return "KRL expired at " + k.Expires.UTC().Format(time.RFC3339)
	}
	if k.IsRevoked(cert) {
		return "certificate revoked"
	}
	return ""
}

// readPrincipals reads dir/user. A missing file or one with no principal
// is a refusal (sshd would refuse anyway); any other error is an error.
func readPrincipals(dir, user string) (principals []string, refusal string, err error) {
	if dir == "" {
		return nil, "", errors.New("no principals directory configured")
	}
	b, err := readFile(filepath.Join(dir, user))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "no principals file for the user", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("reading the principals file: %w", err)
	}
	principals = lines(string(b))
	if len(principals) == 0 {
		return nil, "no principals for the user", nil
	}
	return principals, "", nil
}

// readFile reads at most maxInput bytes of a file, refusing a larger one.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxInput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxInput {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxInput)
	}
	return b, nil
}

// lines returns the non-blank lines of s that do not begin with '#',
// trimmed.
func lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func jsonList(l []string) string {
	if len(l) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(l)
	return string(b)
}
