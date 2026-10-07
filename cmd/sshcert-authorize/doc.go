// SPDX-License-Identifier: BSD-3-Clause

// Command sshcert-authorize is an AuthorizedPrincipalsCommand for sshd that
// lets a certificate in only on the hosts its domain grant names, the
// ssh-domain-grant@core.aai.geant.org extension of the GÉANT/EuroHPC SSH CA
// profile. It is a drop-in replacement for GÉANT's ssh-cert-authorize: same
// flags, same arguments, same output; it differs in refusing what GÉANT's
// lets in.
//
//	AuthorizedPrincipalsCommand /usr/local/bin/sshcert-authorize %u %k
//	AuthorizedPrincipalsCommandUser nobody
//
// Usage:
//
//	sshcert-authorize [flags] USER [CERTIFICATE [KEYTYPE]]
//
// USER is the account being logged into (%u); CERTIFICATE is the base64
// certificate blob (%k), or a whole "ssh-...-cert-v01@openssh.com BASE64"
// line, read from stdin when absent; KEYTYPE, if given (%t), must be the
// certificate's type.
//
// On success it prints the principals listed for USER in
// --principals-dir/USER, one per line, and exits 0: sshd then lets the
// certificate in if one of its principals is among them. On any refusal it
// prints nothing and exits 1, and sshd refuses the certificate.
//
// A certificate is refused when
//
//   - it does not parse, or is not a user certificate;
//   - --krl is given and the list does not load, has expired, or revokes it;
//   - it has no domain grant, unless --allow-no-grant is given;
//   - its domain grant is malformed, whatever the flags: a grant that cannot
//     be read is never taken for an absent one;
//   - no pattern of its grant matches the host's domain;
//   - USER has no principals file, or an empty one.
//
// The host's domain is --domain, or the variable named by --domain-env, or
// the lines of --domain-file (blank lines and lines beginning with '#'
// ignored; several lines are several names for the host, any of which may
// match).
//
// # Why fail-closed
//
// GÉANT's ssh-cert-authorize lets in a certificate that carries no domain
// grant ("might be valid for non-domain-based auth"), and one whose grant it
// cannot parse, or that is empty. A site that trusts several CAs in
// TrustedUserCAKeys -- the federation's and its own, say -- then lets in a
// certificate from any of them on every host, with no domain check at all.
// This command refuses it, unless --allow-no-grant says otherwise.
//
// Logs are key=value lines, to syslog (facility AUTH) by default, to stderr
// with --syslog=false. sshd discards the command's stderr, so use syslog in
// production.
package main
