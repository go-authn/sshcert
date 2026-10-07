// SPDX-License-Identifier: BSD-3-Clause

package sshcert

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// FuzzParseDomainGrant: ParseDomainGrant never panics, and what it accepts
// is canonical: valid JSON that encoding/json reads as the same strings,
// written back byte for byte by EncodeDomainGrant, every pattern valid.
func FuzzParseDomainGrant(f *testing.F) {
	for _, v := range specVectors {
		b, _ := hex.DecodeString(v.hex)
		f.Add(string(b[4:]))
	}
	for _, s := range []string{``, `null`, `[""]`, `["a.example.org",]`, "[\"a\\u002e.b\"]",
		`["A.example.org","a.example.org"]`, "[\"a\"] ", `[1]`, `{"a":"b"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseDomainGrant(s)
		if err != nil {
			if p != nil {
				t.Fatalf("an error and patterns %q", p)
			}
			return
		}
		var j []string
		if err := json.Unmarshal([]byte(s), &j); err != nil || j == nil || !slices.Equal(j, p) {
			t.Fatalf("accepted %q as %q; encoding/json reads %q, %v", s, p, j, err)
		}
		if e, err := EncodeDomainGrant(p); err != nil || e != s {
			t.Fatalf("accepted %q; EncodeDomainGrant writes %q, %v", s, e, err)
		}
		if len(p) > MaxPatterns {
			t.Fatalf("%d patterns", len(p))
		}
		for _, q := range p {
			if ValidatePattern(q) != nil {
				t.Fatalf("accepted an invalid pattern %q", q)
			}
		}
	})
}

// FuzzMatchDomain: MatchDomain never panics; on a valid pattern and host
// it agrees with the regular-expression reading of the specification; it
// ignores ASCII case; and a match never spans labels.
func FuzzMatchDomain(f *testing.F) {
	for _, c := range matchCases {
		f.Add(c.pattern, c.host)
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		got := MatchDomain(pattern, host)
		valid := ValidatePattern(pattern) == nil && validateName(host, false) == nil
		if !valid {
			if got {
				t.Fatalf("MatchDomain(%q, %q): an invalid input matched", pattern, host)
			}
			return
		}
		if want := specMatch(pattern, host); got != want {
			t.Fatalf("MatchDomain(%q, %q) = %v, the specification's reading %v", pattern, host, got, want)
		}
		if MatchDomain(strings.ToUpper(pattern), strings.ToLower(host)) != got {
			t.Fatalf("MatchDomain(%q, %q) depends on case", pattern, host)
		}
		if got && strings.Count(pattern, ".") != strings.Count(host, ".") {
			t.Fatalf("MatchDomain(%q, %q) crossed a label", pattern, host)
		}
	})
}
