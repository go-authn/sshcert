# sshcert

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/sshcert.svg)](https://pkg.go.dev/github.com/go-authn/sshcert)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/sshcert/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/sshcert/actions/workflows/ci.yml)

**SSH user certificates for a federation**: the domain-grant extension of
the GÉANT / EuroHPC SSH CA profile, and `sshcert-authorize`, a
**fail-closed** `AuthorizedPrincipalsCommand` that is a drop-in replacement
for GÉANT's `ssh-cert-authorize`. Pure Go, `CGO_ENABLED=0`.

```go
// An issuer: a certificate for the hosts of one hosting entity.
cert := &ssh.Certificate{ /* key, principal, validity... */ }
err := sshcert.SetDomainGrant(cert, []string{"*.lumi.example.eu", "login.example.org"})
cert.SignCert(rand.Reader, ca)

// A host: is this certificate meant for me?
patterns, present, err := sshcert.DomainGrant(cert)
if !present || err != nil || !sshcert.Grants(patterns, "login.example.org") {
	// refuse
}
```

## The extension

The EuroHPC Federation Platform's SSH CA
([overview](https://integration.docs.my-eurohpc.eu/aai/ssh-ca-overview/),
[trust](https://integration.docs.my-eurohpc.eu/aai/ssh-ca-trust/),
[authorisation](https://integration.docs.my-eurohpc.eu/aai/ssh-ca-authz/))
issues Ed25519 user certificates valid for one hour, with one principal, the
user's MyAccessID identifier (`<id>@myaccessid.org`), and the extension
**`ssh-domain-grant@core.aai.geant.org`**, which lists the host names the
certificate is meant for. Sites trust the CA with `TrustedUserCAKeys`, the
key fetched as `{"PublicKey": "..."}` from `https://sshca.my-eurohpc.eu/config`,
and filter certificates by domain in `AuthorizedPrincipalsCommand`: sshd
itself ignores the extension.

The specification is `docs/ssh-domain-grant-ext.md` in GÉANT's
[ssh-cert-tool](https://gitlab.geant.org/core-aai-platform/ssh-cert-tool)
(Apache-2.0). The extension's data is an SSH string holding a compact JSON
array of patterns, and `*` "matches one or more characters within a single
label":

| pattern | matches | does not match |
| --- | --- | --- |
| `login.example.org` | `login.example.org`, `LOGIN.example.org` | `www.login.example.org` |
| `*.example.org` | `a.example.org` | `example.org`, `a.b.example.org` |
| `prod-*.example.org` | `prod-1.example.org` | `prod-.example.org` |
| `*.*.example.org` | `a.b.example.org` | `a.example.org` |

### The wire, and golang.org/x/crypto/ssh

`EncodeDomainGrant` returns the bare JSON, `["a.example.org"]`, to store in
`ssh.Certificate.Permissions.Extensions`. x/crypto/ssh wraps a non-empty
extension value in one more SSH string when it marshals a certificate
(`marshalTuples`) and strips it when it parses one (`parseTuples`), so the
data field on the wire is `string(json)`: exactly the specification's test
vectors, byte for byte (`TestWireMatchesTheSpecificationsVectors` walks the
certificate's bytes). Putting the length prefix in the map value yourself
would double it. A data field holding the bare JSON with no inner string, as
a careless CA might write, does not parse at all.

`ssh-keygen -s ... -O "extension:ssh-domain-grant@core.aai.geant.org=VALUE"`
encodes VALUE the same way, and `ssh-keygen -L` prints the data field of an
extension it does not know as hex (`UNKNOWN OPTION: 000000145b22...`), which
makes it an independent judge.

### The extension's name

The specification, GÉANT's tools and the EuroHPC authorisation page all spell
it `ssh-domain-grant@core.aai.geant.org`, and certificates carry that name.
This package exports it as `sshcert.DomainGrantExtension`; `--extension`
names another one.

### Strict reading

`ParseDomainGrant` accepts only what `EncodeDomainGrant` writes: a compact
array (no whitespace, nothing after `]`), of strings without JSON escapes,
each a valid pattern (letters, digits, hyphens and `*`; labels of 1 to 63
bytes, not beginning or ending with a hyphen; at most 253 bytes; no `*` in
the rightmost label, so no pattern grants a whole top-level domain), none
repeated, at most 64. `null`, objects, numbers, nested arrays, duplicates and
trailing data are refused. `[]` is accepted and grants nothing: the
specification lets a policy read it as "no restriction" or as "no host";
this package reads it as no host.

A grant that is present and malformed is **never** reported as absent:
`DomainGrant` returns `present == true` and an error.

## `sshcert-authorize`

```
go install github.com/go-authn/sshcert/cmd/sshcert-authorize@latest
sudo install -o root -g root -m 0755 ~/go/bin/sshcert-authorize /usr/local/bin/
echo login.example.org | sudo tee /etc/ssh/cert-allowed-domain.conf
```

`/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/efp-ssh-ca.pub
AuthorizedPrincipalsCommand /usr/local/bin/sshcert-authorize %u %k
AuthorizedPrincipalsCommandUser nobody
```

and, for each local account, the MyAccessID identifiers that may log into
it, one per line, in `/etc/ssh/auth_principals/<account>`. sshd runs the
command only from a path owned by root and writable by no one else.

On success the command prints the account's principals, one per line, and
exits 0; sshd lets the certificate in if one of its principals is among
them. On any refusal it prints nothing and exits 1. It refuses a certificate
that does not parse or is not a user certificate; one with **no** domain
grant (unless `--allow-no-grant`); one whose grant is malformed (always);
one granted for other hosts; and one for an account with no principals.

### A drop-in for GÉANT's `ssh-cert-authorize`

Same arguments (`%u %k`, the certificate on stdin when `%k` is absent; an
optional third argument, `%t`, must be the certificate's type), same flags,
same output, same key=value logs (`action=cert_processed`, `action=denied`,
`action=authorized`, with `serial` and `ca_fingerprint`), to syslog facility
AUTH by default:

| flag | default | |
| --- | --- | --- |
| `--domain` | | the host's name; overrides the two below |
| `--domain-env` | | a variable holding it |
| `--domain-file` | `/etc/ssh/cert-allowed-domain.conf` | one name per line (`#` comments; several lines are several names) |
| `--principals-dir` | `/etc/ssh/auth_principals` | one file per account |
| `--extension` | `ssh-domain-grant@core.aai.geant.org` | |
| `--syslog` | `true` | `--syslog=false` logs to stderr, which sshd discards |
| `--debug` | `false` | |
| `--allow-no-grant` | `false` | **new**: let in a certificate with no grant, as GÉANT's tool does |
| `--krl FILE` | | **new**: see below |

What differs is what it refuses, and the matching of the specification:

| | GÉANT's `ssh-cert-authorize` | `sshcert-authorize` |
| --- | --- | --- |
| no domain grant | **lets it in** | refuses (`--allow-no-grant` to let it in) |
| grant `[]`, `null`, `{}`, `[1]`, unparseable JSON | **lets it in**: reads no domains, as if absent | refuses, whatever the flags |
| grant with whitespace, escapes, duplicates | reads it | refuses (not compact) |
| `prod-*.x` against `prod-.x` | matches (`*` matches nothing) | no match (`*` is one or more) |
| `Login.Example.org` against `login.example.org` | no match (case-sensitive) | matches (DNS names, RFC 4343) |
| `?`, `[...]`, `\` in a pattern | read as `path.Match` syntax | invalid pattern |
| account name with `/` | joined to the principals directory | refused |
| empty `--principals-dir` | reads `./<account>` | refused |

### Why fail-closed: the multi-CA scenario

GÉANT's `authorize.go`, when the certificate yields no domain: *"No domains
in certificate - might be valid for non-domain-based auth"*, and the
certificate goes on to the principals. Step by step:

1. A site trusts the federation's CA, which grants domains. It also trusts a
   second CA in the same `TrustedUserCAKeys` file: its own CA for staff, a
   test CA, another federation's. (The EuroHPC trust page itself appends the
   staging and production CAs to one file.)
2. It filters with `ssh-cert-authorize`, believing certificates are
   restricted to its domain.
3. The second CA issues a certificate with no domain grant -- it has never
   heard of the extension -- for a principal that appears in some
   account's principals file (or that the CA lets its users choose).
4. sshd accepts the CA and runs the command; the command finds no domain,
   lets the certificate through and prints the account's principals; sshd
   matches the principal. **Logged in, with no domain check at all.**
5. The same holds for a certificate from the federation's own CA whose grant
   is `[]`, or malformed: GÉANT's parser reads no domains, which is the
   no-grant path.

The domain filter is only a filter if a certificate that does not say where
it may be used is refused. `sshcert-authorize` refuses it; a site that
really wants GÉANT's behaviour says so with `--allow-no-grant`, and even then
a grant that is present but malformed is refused.

### `--krl` or sshd's `RevokedKeys`?

`RevokedKeys` is sshd's own check, made before the command runs, for every
key and certificate, and it also revokes a CA key; prefer it. `--krl FILE`
checks an OpenSSH KRL (read with [go-authn/krl](https://github.com/go-authn/krl))
in the command, and adds two things sshd does not do: it refuses **every**
certificate once the list has expired (the `expires@go-authn.github.io`
extension, which sshd ignores), so a stale copy cannot keep a revoked
certificate valid; and it refuses every certificate when the list cannot be
read. Use it when the list is fetched and may go stale, or when sshd's
configuration cannot be changed; it can be combined with `RevokedKeys`.
With one-hour certificates, revocation matters little for the federation's
CA; it matters for a long-lived site CA.

## Judged by others

The tests do not let the package agree with itself.

| test | judge |
| --- | --- |
| `TestWireMatchesTheSpecificationsVectors` | the specification's five hex vectors, against the certificate's bytes |
| `TestOracleSshKeygenReadsWhatWeWrite` | `ssh-keygen -L` reads the vectors in certificates signed here |
| `TestOracleWeReadWhatSshKeygenWrites` | certificates signed by `ssh-keygen -O extension:...`: same bytes as ours, same patterns read |
| `TestMatchDomain`, `FuzzMatchDomain` | an independent reading of the specification as a regular expression (`*` is `[^.]+`, case-insensitive) |
| `FuzzParseDomainGrant` | `encoding/json` reads what the parser accepts as the same strings, and `EncodeDomainGrant` writes it back byte for byte |
| `TestGEANTJudgeMatch` | GÉANT's `cert.MatchDomain` on ~60,000 pairs: every divergence must fall in a category ruled on below |
| `TestGEANTJudgeParse` | GÉANT's `cert.ParseCertificate` on 21 extension values |
| `TestSSHDJudges` | real sshd logins (below) |

GÉANT's code runs as a judge through `testdata/geantjudge/build.sh`, which
clones ssh-cert-tool at a pinned commit and builds `testdata/geantjudge/main.go`
against its `pkg/cert`, and its `ssh-cert-authorize` unmodified. Nothing is
sent to GÉANT's repository.

### Divergences from GÉANT's matcher

At the pinned commit, of 60,048 pairs 57,692 agree. The others, and the
ruling from the specification's text:

| category | pairs | example | ruling |
| --- | --- | --- | --- |
| empty wildcard | 374 | `a*b*c.example.com` / `abc.example.com`: GÉANT matches | "one or more characters": no match |
| case | 124 | `Login.Example.COM` / `login.example.com`: GÉANT does not match | domain names are case-insensitive: match |
| invalid input | 1,858 | `*.example.com` / `.example.com`: GÉANT matches | "reject malformed domain names": no match |

### Real sshd

On the `judges` CI lane, four sshds trust two CAs (a federation's, which
grants, and a second one, which does not), with `AuthorizedPrincipalsCommand`
set to this command, to it with `--allow-no-grant`, to it with `--krl`, and
to GÉANT's `ssh-cert-authorize`. Certificates are signed by `ssh-keygen` and
by this package; `ssh` logs in or not:

| certificate | ours | `--allow-no-grant` | `--krl` | GÉANT's |
| --- | --- | --- | --- | --- |
| granted `*.sshcert.test` (ssh-keygen) | in | in | in | in |
| granted the host (this package; revoked in the KRL) | in | in | refused | in |
| granted another domain (both signers) | refused | refused | refused | refused |
| no grant, second CA | refused | in | refused | **in** |
| no grant, federation's CA | refused | in | refused | **in** |
| grant `null` | refused | refused | refused | **in** |
| grant `[]` | refused | refused | refused | **in** |

The last four rows of GÉANT's column are the fail-open, demonstrated.

## Who uses it

- **Issuing: [go-authn/bridge](https://github.com/go-authn/bridge)
  [v0.19.0](https://github.com/go-authn/bridge/tree/v0.19.0).** It is
  an OpenID Connect provider in front of a SAML federation. A client
  configured in the EuroHPC SSH CA profile gets short-lived user certificates
  with one principal and a `source-address`, and its `ssh_domain_grants` are
  written into this extension. bridge checks each pattern at load with
  `ValidatePattern`, then encodes the list with `EncodeDomainGrant`.
  `GET /ssh/config` publishes the CA key the way EFP publishes its own,
  `{"PublicKey":"..."}`. The grant is then read alike by GÉANT's tool, by
  `sshcert-authorize` and by `ssh-keygen`.
- **Enforcing: [go-fileshare/fileshare](https://github.com/go-fileshare/fileshare)
  [v0.22.1](https://github.com/go-fileshare/fileshare/releases/tag/v0.22.1).**
  Its SFTP server has `ssh_domains`, which reads the grant with
  `DomainGrant` and `Grants` and is fail-closed in the same way as
  `sshcert-authorize`. It refuses a certificate with no grant unless
  `ssh_accept_ungranted` is set, and it always refuses a malformed grant. A
  certificate's `source-address` is enforced there too.
  [go-authn/bridge#54](https://github.com/go-authn/bridge/pull/54) adds an
  interop test that logs in to the released fileshare with an EFP-profile
  certificate. It gets in where both the grant and the address allow it, and is
  refused where either does not.

## Release binaries

Each release carries `sshcert-authorize` for linux, darwin and windows on amd64 and arm64
(pure Go, `CGO_ENABLED=0`), a `SHA256SUMS` manifest, and a build provenance
attestation per binary, made by this repository's release workflow at the
tag. Check a download before running it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify sshcert-authorize-linux-amd64 --repo go-authn/sshcert
```

`sshcert-authorize -version` prints the tag it was built from.

## License

BSD-3-Clause.
