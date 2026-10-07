// SPDX-License-Identifier: BSD-3-Clause

package sshcert

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// DomainGrantExtension is the name of the certificate extension that lists
// the hosts a certificate may be used on, as GÉANT's specification
// (docs/ssh-domain-grant-ext.md in ssh-cert-tool) and GÉANT's tools spell
// it. The EuroHPC documentation writes "ssh-domain-grant@core.aai.org";
// certificates carry this name.
const DomainGrantExtension = "ssh-domain-grant@core.aai.geant.org"

// MaxPatterns is the largest number of patterns a domain grant may hold.
const MaxPatterns = 64

// MaxGrantLength is the longest extension value accepted, in bytes: enough
// for MaxPatterns patterns of MaxPatternLength bytes, quoted and separated.
const MaxGrantLength = 2 + MaxPatterns*(MaxPatternLength+3)

// ErrInvalidGrant is wrapped by every error about a malformed extension
// value.
var ErrInvalidGrant = errors.New("sshcert: invalid domain grant")

// EncodeDomainGrant returns the value to store under DomainGrantExtension
// in ssh.Certificate.Permissions.Extensions for patterns: their compact
// JSON array, `["a.example.org","*.example.org"]`, `[]` for none.
//
// The value is the JSON text itself, with no length prefix:
// golang.org/x/crypto/ssh writes a non-empty extension value as an SSH
// string inside the extension's data field, which is the encoding the
// specification requires ("string <json-array>" inside the data), and
// strips that inner string again when it parses a certificate. So the
// certificate's bytes equal the specification's test vectors (see
// TestWireMatchesTheSpecificationsVectors) and ssh-keygen -s -O
// "extension:NAME=VALUE" writes the same bytes for the same VALUE.
//
// Every pattern must pass ValidatePattern; duplicates (ignoring case) and
// more than MaxPatterns patterns are refused.
func EncodeDomainGrant(patterns []string) (string, error) {
	if len(patterns) > MaxPatterns {
		return "", fmt.Errorf("%w: %d patterns, more than %d", ErrInvalidGrant, len(patterns), MaxPatterns)
	}
	seen := make(map[string]bool, len(patterns))
	var b strings.Builder
	b.WriteByte('[')
	for i, p := range patterns {
		if err := ValidatePattern(p); err != nil {
			return "", err
		}
		k := strings.ToLower(p)
		if seen[k] {
			return "", fmt.Errorf("%w: pattern %q appears twice", ErrInvalidGrant, p)
		}
		seen[k] = true
		if i > 0 {
			b.WriteByte(',')
		}
		// A valid pattern holds no character JSON escapes.
		b.WriteByte('"')
		b.WriteString(p)
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return b.String(), nil
}

// SetDomainGrant stores the domain grant for patterns in cert, creating
// its extension map if needed. It is to be called before the certificate
// is signed.
func SetDomainGrant(cert *ssh.Certificate, patterns []string) error {
	v, err := EncodeDomainGrant(patterns)
	if err != nil {
		return err
	}
	if cert.Permissions.Extensions == nil {
		cert.Permissions.Extensions = map[string]string{}
	}
	cert.Permissions.Extensions[DomainGrantExtension] = v
	return nil
}

// ParseDomainGrant parses an extension value, as found in
// ssh.Certificate.Permissions.Extensions, into its patterns.
//
// It is strict, and accepts only what EncodeDomainGrant writes:
//
//   - a JSON array of strings, in compact form: no whitespace anywhere,
//     nothing before '[' or after ']' -- the specification says the JSON
//     "MUST NOT contain whitespace outside of quoted strings";
//   - no JSON escapes: a valid pattern never needs one, so an escape can
//     only make two encodings of one grant, or hide a character;
//   - every pattern valid for ValidatePattern, none repeated (ignoring
//     case), at most MaxPatterns of them, and at most MaxGrantLength bytes
//     in all.
//
// So null, objects, numbers, nested arrays, non-strings, duplicate entries
// and trailing data are refused. `[]` is accepted and yields an empty,
// non-nil list, which grants nothing (the specification lets a policy read
// it either way; this package reads it as no host).
func ParseDomainGrant(value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("%w: empty value", ErrInvalidGrant)
	}
	if len(value) > MaxGrantLength {
		return nil, fmt.Errorf("%w: %d bytes, longer than %d", ErrInvalidGrant, len(value), MaxGrantLength)
	}
	if value[0] != '[' {
		return nil, fmt.Errorf("%w: not a JSON array: begins with %q", ErrInvalidGrant, value[0])
	}
	patterns := []string{}
	seen := map[string]bool{}
	i := 1
	if i < len(value) && value[i] == ']' {
		i++
	} else {
		for {
			if i >= len(value) || value[i] != '"' {
				return nil, fmt.Errorf("%w: expected a string at byte %d", ErrInvalidGrant, i)
			}
			end := strings.IndexByte(value[i+1:], '"')
			if end < 0 {
				return nil, fmt.Errorf("%w: unterminated string at byte %d", ErrInvalidGrant, i)
			}
			p := value[i+1 : i+1+end]
			if strings.IndexByte(p, '\\') >= 0 {
				return nil, fmt.Errorf("%w: JSON escape in pattern %q", ErrInvalidGrant, p)
			}
			if err := ValidatePattern(p); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrInvalidGrant, err)
			}
			k := strings.ToLower(p)
			if seen[k] {
				return nil, fmt.Errorf("%w: pattern %q appears twice", ErrInvalidGrant, p)
			}
			seen[k] = true
			if len(patterns) == MaxPatterns {
				return nil, fmt.Errorf("%w: more than %d patterns", ErrInvalidGrant, MaxPatterns)
			}
			patterns = append(patterns, p)
			i += end + 2
			if i < len(value) && value[i] == ',' {
				i++
				continue
			}
			if i < len(value) && value[i] == ']' {
				i++
				break
			}
			return nil, fmt.Errorf("%w: expected ',' or ']' at byte %d", ErrInvalidGrant, i)
		}
	}
	if i != len(value) {
		return nil, fmt.Errorf("%w: %d bytes of trailing data", ErrInvalidGrant, len(value)-i)
	}
	return patterns, nil
}

// DomainGrant returns the patterns of cert's DomainGrantExtension, and
// whether the extension is present. An extension that is present but does
// not parse gives present == true and an error: a caller deciding access
// must refuse then, never read it as absent.
func DomainGrant(cert *ssh.Certificate) (patterns []string, present bool, err error) {
	return DomainGrantNamed(cert, DomainGrantExtension)
}

// DomainGrantNamed is DomainGrant for an extension of another name.
func DomainGrantNamed(cert *ssh.Certificate, name string) (patterns []string, present bool, err error) {
	if cert == nil {
		return nil, false, errors.New("sshcert: nil certificate")
	}
	v, ok := cert.Permissions.Extensions[name]
	if !ok {
		return nil, false, nil
	}
	patterns, err = ParseDomainGrant(v)
	return patterns, true, err
}
