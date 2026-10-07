// SPDX-License-Identifier: BSD-3-Clause

// Command sshcert-geant-judge runs GÉANT's own code as a judge for the
// differential tests of github.com/go-authn/sshcert. It is not part of this
// module: build.sh copies it into a checkout of GÉANT's ssh-cert-tool
// (Apache-2.0) and builds it there, against GÉANT's pkg/cert.
//
// It reads requests on stdin, one per line, fields separated by tabs and
// hex-encoded so that any byte can be sent, and answers one line each:
//
//	match <pattern> <host>     -> "true" | "false"     cert.MatchDomain
//	cert  <certificate blob>   -> "error" | "none" | <hex of the JSON list>
//	                              what cert.ParseCertificate extracts as
//	                              Extensions["domains"]
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gitlab.geant.org/core-aai-platform/ssh-cert-tool/pkg/cert"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	// One answer per request, flushed: the caller waits for it.
	answer := func(s any) { fmt.Fprintln(out, s); out.Flush() }
	for in.Scan() {
		f := strings.Split(in.Text(), "\t")
		args := make([]string, len(f)-1)
		for i, h := range f[1:] {
			b, err := hex.DecodeString(h)
			if err != nil {
				fmt.Fprintln(os.Stderr, "bad request:", err)
				os.Exit(2)
			}
			args[i] = string(b)
		}
		switch {
		case f[0] == "match" && len(args) == 2:
			answer(cert.MatchDomain(args[0], args[1]))
		case f[0] == "cert" && len(args) == 1:
			c, err := cert.ParseCertificate(base64.StdEncoding.EncodeToString([]byte(args[0])), "ssh-domain-grant@core.aai.geant.org")
			if err != nil {
				answer("error")
				continue
			}
			d, ok := c.Extensions["domains"].([]string)
			if !ok {
				answer("none")
				continue
			}
			j, _ := json.Marshal(d)
			answer(hex.EncodeToString(j))
		default:
			fmt.Fprintln(os.Stderr, "bad request:", f[0])
			os.Exit(2)
		}
	}
}
