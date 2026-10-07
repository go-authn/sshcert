// SPDX-License-Identifier: BSD-3-Clause

// Package sshcert handles the domain-grant extension of SSH user
// certificates, ssh-domain-grant@core.aai.geant.org, from the SSH CA
// profile of GÉANT's Core AAI platform that the EuroHPC federation
// (MyAccessID) uses.
//
// A certificate issued under that profile carries one principal, the
// user's MyAccessID identifier, and in this extension the list of host
// names, possibly with wildcards, it may be used on:
//
//	["*.lumi.example.eu","login.example.org"]
//
// A site trusting the CA then refuses, in sshd's AuthorizedPrincipalsCommand,
// a certificate that was not granted for it. The command
// cmd/sshcert-authorize does that, and refuses as well a certificate with
// no grant at all (see its documentation for why).
//
//	// Issuing
//	cert := &ssh.Certificate{ /* ... */ }
//	if err := sshcert.SetDomainGrant(cert, []string{"*.example.org"}); err != nil { ... }
//	cert.SignCert(rand.Reader, ca)
//
//	// Checking
//	patterns, present, err := sshcert.DomainGrant(cert)
//	if !present || err != nil || !sshcert.Grants(patterns, "login.example.org") {
//		// refuse
//	}
//
// # The specification
//
// The extension is specified in docs/ssh-domain-grant-ext.md of GÉANT's
// ssh-cert-tool (https://gitlab.geant.org/core-aai-platform/ssh-cert-tool).
// Its data field is an SSH string holding a compact JSON array of domain
// patterns, where '*' "matches one or more characters within a single
// label". This package writes exactly the specification's test vectors and
// is strict in what it reads (ParseDomainGrant); MatchDomain follows the
// specification's wording where GÉANT's own matcher does not (see the
// README).
package sshcert
