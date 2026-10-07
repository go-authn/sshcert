// SPDX-License-Identifier: BSD-3-Clause

package sshcert

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// specMatch is a second, independent reading of the specification's
// sentence, "The wildcard character `*` matches one or more characters
// within a single label of a domain name": a regular expression in which
// '*' is [^.]+, compared without regard to case. MatchDomain must agree
// with it on every valid pattern and host.
func specMatch(pattern, host string) bool {
	var b strings.Builder
	b.WriteString(`(?i)\A`)
	for i, part := range strings.Split(pattern, "*") {
		if i > 0 {
			b.WriteString(`[^.]+`)
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String()).MatchString(host)
}

// The specification's examples, and the cases its wording settles.
var matchCases = []struct {
	pattern, host string
	want          bool
}{
	// "Exact match: example.com - matches only the specified domain"
	{"example.com", "example.com", true},
	{"example.com", "www.example.com", false},
	{"example.com", "example.co", false},
	{"example.com", "example.com.au", false},
	{"test.example.com", "test.example.com", true},
	{"test.org", "test.org", true},
	// "Wildcard subdomain: *.example.com - matches any direct subdomain"
	{"*.example.com", "www.example.com", true},
	{"*.example.com", "a.example.com", true},
	{"*.example.com", "example.com", false},
	{"*.example.com", "a.b.example.com", false}, // one label only
	{"*.example.com", ".example.com", false},    // one or more: not none
	{"*.example.com", "www.example.org", false},
	{"*.example.com", "wwwexample.com", false},
	// "Pattern matching: prod-*.example.com"
	{"prod-*.example.com", "prod-1.example.com", true},
	{"prod-*.example.com", "prod-web-a.example.com", true},
	{"prod-*.example.com", "prod-.example.com", false}, // one or more
	{"prod-*.example.com", "prod.example.com", false},
	{"prod-*.example.com", "dev-1.example.com", false},
	{"prod-*.example.com", "prod-1.a.example.com", false},
	// "Multi-level wildcards: *.*.example.com"
	{"*.*.example.com", "a.b.example.com", true},
	{"*.*.example.com", "a.example.com", false},
	{"*.*.example.com", "a.b.c.example.com", false},
	// Several wildcards in a label; backtracking.
	{"a*b*c.example.com", "abc.example.com", false},
	{"a*b*c.example.com", "axbyc.example.com", true},
	{"a*b*c.example.com", "axxbbbyyc.example.com", true},
	{"a*b*c.example.com", "axbc.example.com", false},
	{"*a.example.com", "aaa.example.com", true},
	{"*a.example.com", "a.example.com", false},
	{"*-*.example.com", "a-b.example.com", true},
	{"*-*.example.com", "a--b.example.com", true},
	{"*-*.example.com", "-b.example.com", false},
	{"*.prod.example.com", "web.prod.example.com", true},
	{"*.prod.example.com", "web.staging.example.com", false},
	// Case: DNS names compare without regard to case (RFC 4343).
	{"Login.Example.COM", "login.example.com", true},
	{"*.EXAMPLE.com", "WWW.example.COM", true},
	{"x*Y.example.com", "XaaY.example.com", true},
	// Invalid patterns and hosts match nothing.
	{"", "", false},
	{"*", "localhost", false},
	{"a.*", "a.b", false},
	{"a?.example.com", "ab.example.com", false},
	{"[ab].example.com", "a.example.com", false},
	{`a\*.example.com`, `a*.example.com`, false},
	{"example.com.", "example.com.", false},
	{"example.com", "example.com.", false},
	{"*.example.com", "*.example.com", false},
	{"a..example.com", "a..example.com", false},
	{"a_b.example.com", "a_b.example.com", false},
	{"localhost", "localhost", true},
}

func TestMatchDomain(t *testing.T) {
	for _, c := range matchCases {
		if got := MatchDomain(c.pattern, c.host); got != c.want {
			t.Errorf("MatchDomain(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
		if ValidatePattern(c.pattern) == nil && validateName(c.host, false) == nil {
			if s := specMatch(c.pattern, c.host); s != c.want {
				t.Errorf("the regular-expression reading disagrees on (%q, %q): %v", c.pattern, c.host, s)
			}
		}
	}
}

func TestGrants(t *testing.T) {
	if Grants(nil, "a.example.org") || Grants([]string{}, "a.example.org") {
		t.Error("an empty grant granted a host")
	}
	p := []string{"x.example.org", "*.example.org"}
	if !Grants(p, "a.example.org") || Grants(p, "a.example.com") {
		t.Error("Grants is not the OR of its patterns")
	}
}

func TestValidatePattern(t *testing.T) {
	ok := []string{
		"localhost", "a.example.org", "*.example.org", "*.*.example.org",
		"prod-*-*.example.org", "xn--caf-dma.example.org", "A-1.B.example",
		strings.Repeat("a", 63) + ".org",
		strings.Repeat("abcdefghi.", 25) + "abc", // 253 bytes
	}
	for _, p := range ok {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q): %v", p, err)
		}
	}
	bad := []string{
		"", ".", "a.", ".a", "a..b", "*", "a.*", "a.b*", "*.*",
		strings.Repeat("a", 64) + ".org",
		strings.Repeat("abcdefghi.", 25) + "abcd", // 254 bytes
		"-a.org", "a-.org", "*-.org", "-*.org", "a b.org", "a_b.org",
		"a?.org", "[a].org", `a\b.org`, "a/b.org", "a\x00.org", "café.org",
		"a\n.org", "a:22.org", "a@b.org",
	}
	for _, p := range bad {
		err := ValidatePattern(p)
		if err == nil {
			t.Errorf("ValidatePattern(%.40q) accepted it", p)
		} else if !errors.Is(err, ErrInvalidPattern) {
			t.Errorf("ValidatePattern(%.40q): %v does not wrap ErrInvalidPattern", p, err)
		}
	}
	if err := validateName("a.b*", false); err == nil || !strings.Contains(err.Error(), "host name") {
		t.Errorf("a host with a wildcard: %v", err)
	}
	if err := validateName("", false); err == nil || !strings.Contains(err.Error(), "host name") {
		t.Errorf("an empty host: %v", err)
	}
}
