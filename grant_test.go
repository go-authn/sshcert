// SPDX-License-Identifier: BSD-3-Clause

package sshcert

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEncodeDomainGrant(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, `[]`},
		{[]string{}, `[]`},
		{[]string{"a.example.org"}, `["a.example.org"]`},
		{[]string{"*.example.org", "B.example.ORG"}, `["*.example.org","B.example.ORG"]`},
	} {
		got, err := EncodeDomainGrant(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("EncodeDomainGrant(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
		// What it writes is what encoding/json writes, compact.
		if tc.in != nil {
			j, _ := json.Marshal(tc.in)
			if string(j) != got {
				t.Errorf("%q: encoding/json writes %s", tc.in, j)
			}
		}
	}
	for _, in := range [][]string{
		{"a.example.org", "A.Example.Org"},
		{"bad..example.org"},
		{"*"},
		{""},
		manyPatterns(MaxPatterns + 1),
	} {
		if got, err := EncodeDomainGrant(in); err == nil {
			t.Errorf("EncodeDomainGrant(%.60q) = %q, want an error", in, got)
		}
	}
	if _, err := EncodeDomainGrant(manyPatterns(MaxPatterns)); err != nil {
		t.Errorf("MaxPatterns patterns: %v", err)
	}
}

func manyPatterns(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%d.example.org", i)
	}
	return out
}

func TestSetDomainGrant(t *testing.T) {
	c := &ssh.Certificate{}
	if err := SetDomainGrant(c, []string{"a.example.org"}); err != nil {
		t.Fatal(err)
	}
	if c.Permissions.Extensions[DomainGrantExtension] != `["a.example.org"]` {
		t.Fatalf("%q", c.Permissions.Extensions)
	}
	c.Permissions.Extensions["permit-pty"] = ""
	if err := SetDomainGrant(c, []string{"b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if len(c.Permissions.Extensions) != 2 || c.Permissions.Extensions[DomainGrantExtension] != `["b.example.org"]` {
		t.Fatalf("%q", c.Permissions.Extensions)
	}
	if err := SetDomainGrant(c, []string{"*"}); err == nil {
		t.Fatal("an invalid pattern was stored")
	}
	if c.Permissions.Extensions[DomainGrantExtension] != `["b.example.org"]` {
		t.Fatal("a refused grant replaced the previous one")
	}
}

func TestParseDomainGrantAccepts(t *testing.T) {
	for in, want := range map[string][]string{
		`[]`:                                     {},
		`["a.example.org"]`:                      {"a.example.org"},
		`["*.example.org","login.Example.ORG"]`:  {"*.example.org", "login.Example.ORG"},
		`["prod-*-*.x.example.org","localhost"]`: {"prod-*-*.x.example.org", "localhost"},
	} {
		got, err := ParseDomainGrant(in)
		if err != nil || !slices.Equal(got, want) || got == nil {
			t.Errorf("ParseDomainGrant(%s) = %q, %v; want %q", in, got, err, want)
		}
	}
	many, _ := EncodeDomainGrant(manyPatterns(MaxPatterns))
	if got, err := ParseDomainGrant(many); err != nil || len(got) != MaxPatterns {
		t.Errorf("MaxPatterns patterns: %d %v", len(got), err)
	}
}

// TestParseDomainGrantRefuses: everything that is not the compact array
// of valid, distinct patterns EncodeDomainGrant writes. Each of these is
// a value GÉANT's parser either accepts or reads as "no domains"
// (TestGEANTJudgeParse shows which).
func TestParseDomainGrantRefuses(t *testing.T) {
	// Longer than MaxGrantLength, and one pattern too many (distinct ones).
	long := `["` + strings.Repeat("a", MaxGrantLength) + `"]`
	tooMany := `["` + strings.Join(manyPatterns(MaxPatterns+1), `","`) + `"]`
	for _, in := range []string{
		``,
		`null`,
		`{}`,
		`{"a":"x.example.org","a":"y.example.org"}`,
		`"a.example.org"`,
		`[`,
		`[,]`,
		`[1]`,
		`[true]`,
		`[null]`,
		`[["a.example.org"]]`,
		`[{"a":1}]`,
		`["a.example.org",]`,
		`["a.example.org"`,
		`["a.example.org`,
		`["a.example.org"]]`,
		`["a.example.org"] `,
		`["a.example.org"]x`,
		`["a.example.org"][]`,
		` ["a.example.org"]`,
		`[ "a.example.org"]`,
		`["a.example.org" ]`,
		`["a.example.org", "b.example.org"]`,
		"[\"a.example.org\"]\n",
		"[\"a.example.org\"]\x00",
		`["a.example.org";"b"]`,
		"[\"a\\u002eexample.org\"]",
		`["a\".example.org"]`,
		`["a.example.org","A.EXAMPLE.ORG"]`,
		`[""]`,
		`["*"]`,
		`["a.*"]`,
		`["a..example.org"]`,
		`[".example.org"]`,
		`["example.org."]`,
		`["a b.example.org"]`,
		`["a_b.example.org"]`,
		`["a?.example.org"]`,
		`["[ab].example.org"]`,
		`["-a.example.org"]`,
		"[\"caf\xc3\xa9.example.org\"]",
		"[\"\xff.example.org\"]",
		long,
		tooMany,
		`[` + strings.Repeat(`"`+strings.Repeat("a", 60)+`.example.org",`, MaxPatterns) + `"z"]`,
	} {
		got, err := ParseDomainGrant(in)
		if err == nil {
			t.Errorf("ParseDomainGrant(%.80q) = %q, want an error", in, got)
			continue
		}
		if !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("ParseDomainGrant(%.80q): %v does not wrap ErrInvalidGrant", in, err)
		}
	}
}

func TestDomainGrant(t *testing.T) {
	if _, _, err := DomainGrant(nil); err == nil {
		t.Error("nil certificate: no error")
	}
	c := &ssh.Certificate{}
	if p, present, err := DomainGrant(c); p != nil || present || err != nil {
		t.Errorf("no extensions: %q %v %v", p, present, err)
	}
	c.Permissions.Extensions = map[string]string{"permit-pty": ""}
	if p, present, err := DomainGrant(c); p != nil || present || err != nil {
		t.Errorf("no grant: %q %v %v", p, present, err)
	}
	// A flag-style extension (empty data) of the grant's name is present
	// and malformed: never absent.
	c.Permissions.Extensions[DomainGrantExtension] = ""
	if _, present, err := DomainGrant(c); !present || err == nil {
		t.Errorf("empty grant: present %v err %v", present, err)
	}
	c.Permissions.Extensions[DomainGrantExtension] = `["a.example.org"] `
	if _, present, err := DomainGrant(c); !present || err == nil {
		t.Errorf("malformed grant: present %v err %v", present, err)
	}
	c.Permissions.Extensions["other@example.org"] = `["b.example.org"]`
	if p, present, err := DomainGrantNamed(c, "other@example.org"); !present || err != nil || !slices.Equal(p, []string{"b.example.org"}) {
		t.Errorf("named: %q %v %v", p, present, err)
	}
}

// TestParseDomainGrantNamesAnEscape: an escape is refused as one, not as
// the invalid character ValidatePattern would also find, so the log says
// what the issuer did.
func TestParseDomainGrantNamesAnEscape(t *testing.T) {
	for _, in := range []string{"[\"a\\u002eexample.org\"]", `["a\\.example.org"]`} {
		_, err := ParseDomainGrant(in)
		if err == nil || !strings.Contains(err.Error(), "JSON escape") {
			t.Errorf("ParseDomainGrant(%s): %v, want a JSON escape refusal", in, err)
		}
	}
}
