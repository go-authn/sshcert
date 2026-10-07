// SPDX-License-Identifier: BSD-3-Clause

package sshcert

import (
	"errors"
	"fmt"
	"strings"
)

// Limits on a domain pattern. A pattern is a DNS name, possibly with
// wildcards, so it is held to the lengths of RFC 1035 section 2.3.4.
const (
	// MaxPatternLength is the longest pattern accepted, in bytes: the
	// longest DNS name in its dotted text form.
	MaxPatternLength = 253
	// MaxLabelLength is the longest label of a pattern, in bytes.
	MaxLabelLength = 63
)

// ErrInvalidPattern is wrapped by every error ValidatePattern returns.
var ErrInvalidPattern = errors.New("sshcert: invalid domain pattern")

// ValidatePattern reports whether p is a domain pattern this package
// accepts. The extension's specification requires implementations to
// "reject malformed domain names" and to "enforce maximum pattern length
// limits" without saying what they are; this package's rules are:
//
//   - at most MaxPatternLength bytes, and labels separated by single dots,
//     each of 1 to MaxLabelLength bytes: no empty label, so no leading,
//     trailing or doubled dot;
//   - a label is made of ASCII letters, digits, hyphens and the wildcard
//     '*', and does not begin or end with a hyphen (RFC 1123 host names);
//   - the rightmost label has no wildcard, so no pattern grants every
//     name under a top-level domain, or every single-label name. The
//     specification asks implementations to limit wildcard matching.
//
// Anything else -- other characters, among them '?', '[' and '\' that a
// shell-style matcher would read as syntax, non-ASCII letters (use the
// A-label, "xn--..."), underscores, spaces -- is refused.
func ValidatePattern(p string) error {
	return validateName(p, true)
}

// validateName checks a pattern (wildcards allowed) or a host name (none).
func validateName(p string, wildcards bool) error {
	what := "pattern"
	if !wildcards {
		what = "host name"
	}
	if p == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidPattern, what)
	}
	if len(p) > MaxPatternLength {
		return fmt.Errorf("%w: %s is %d bytes, longer than %d", ErrInvalidPattern, what, len(p), MaxPatternLength)
	}
	labels := strings.Split(p, ".")
	for i, l := range labels {
		if l == "" {
			return fmt.Errorf("%w: %s %q has an empty label", ErrInvalidPattern, what, p)
		}
		if len(l) > MaxLabelLength {
			return fmt.Errorf("%w: %s %q has a label of %d bytes, longer than %d", ErrInvalidPattern, what, p, len(l), MaxLabelLength)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: %s %q has a label beginning or ending with a hyphen", ErrInvalidPattern, what, p)
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			switch {
			case isLDH(c):
			case c == '*' && wildcards:
				if i == len(labels)-1 {
					return fmt.Errorf("%w: pattern %q has a wildcard in its rightmost label", ErrInvalidPattern, p)
				}
			default:
				return fmt.Errorf("%w: %s %q contains %q", ErrInvalidPattern, what, p, c)
			}
		}
	}
	return nil
}

func isLDH(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-'
}

// MatchDomain reports whether host is matched by pattern, following the
// specification of the ssh-domain-grant extension: "The wildcard character
// `*` matches one or more characters within a single label of a domain
// name (labels are separated by dots)". So:
//
//   - pattern and host have the same number of labels, and each label of
//     the host is matched by the label of the pattern in the same place:
//     a wildcard never crosses a dot;
//   - '*' stands for one or more characters, never for none, and may
//     appear several times in a label ("prod-*-*");
//   - letters are compared without regard to ASCII case, as DNS names
//     are (RFC 4343).
//
// A pattern ValidatePattern refuses matches nothing, and neither does a
// host that is not a valid DNS name in the same sense (which includes a
// host containing '*'). A trailing dot is not removed from either: give
// the host as a relative name, "login.example.org".
func MatchDomain(pattern, host string) bool {
	if ValidatePattern(pattern) != nil || validateName(host, false) != nil {
		return false
	}
	pl := strings.Split(pattern, ".")
	hl := strings.Split(host, ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if !matchLabel(pl[i], hl[i]) {
			return false
		}
	}
	return true
}

// Grants reports whether any of patterns matches host: a domain grant
// lists the hosts a certificate may be used on, and several patterns are
// alternatives ("they SHOULD be treated as a logical OR"). An empty list
// grants nothing.
func Grants(patterns []string, host string) bool {
	for _, p := range patterns {
		if MatchDomain(p, host) {
			return true
		}
	}
	return false
}

// Tokens of a compiled label: a byte (lower-cased), or one of these.
const (
	anyOne  = -1 // exactly one character
	anyMany = -2 // zero or more characters
)

// matchLabel matches one label. Each '*' is compiled to "one character,
// then zero or more", so that the classic linear wildcard algorithm, with
// one backtracking point, implements "one or more" exactly.
func matchLabel(p, h string) bool {
	t := make([]int, 0, len(p)+4)
	for i := 0; i < len(p); i++ {
		if p[i] == '*' {
			t = append(t, anyOne, anyMany)
		} else {
			t = append(t, int(lower(p[i])))
		}
	}
	i, j := 0, 0
	star, mark := -1, 0
	for j < len(h) {
		switch {
		case i < len(t) && (t[i] == anyOne || t[i] == int(lower(h[j]))):
			i++
			j++
		case i < len(t) && t[i] == anyMany:
			star, mark = i, j
			i++
		case star >= 0:
			i = star + 1
			mark++
			j = mark
		default:
			return false
		}
	}
	for i < len(t) && t[i] == anyMany {
		i++
	}
	return i == len(t)
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
