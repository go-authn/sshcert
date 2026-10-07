// SPDX-License-Identifier: BSD-3-Clause

package sshcert

// Differential tests against GÉANT's own code, run as a judge: the
// program testdata/geantjudge/main.go built against GÉANT's pkg/cert by
// testdata/geantjudge/build.sh. SSHCERT_GEANT_JUDGE names it; without it
// the tests are skipped, unless SSHCERT_REQUIRE_GEANT=1 (the CI lane that
// builds it), where its absence is a failure.
//
// Every divergence must fall in a category whose ruling, from the
// specification's text, is written below; an unexplained one fails.

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type geantJudge struct {
	t   *testing.T
	in  io.WriteCloser
	out *bufio.Scanner
}

func newGEANTJudge(t *testing.T) *geantJudge {
	t.Helper()
	bin := os.Getenv("SSHCERT_GEANT_JUDGE")
	if bin == "" {
		if os.Getenv("SSHCERT_REQUIRE_GEANT") == "1" {
			t.Fatal("SSHCERT_REQUIRE_GEANT=1 and SSHCERT_GEANT_JUDGE is not set; build it with testdata/geantjudge/build.sh")
		}
		t.Skip("SSHCERT_GEANT_JUDGE not set: build GÉANT's judge with testdata/geantjudge/build.sh")
	}
	cmd := exec.Command(bin)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	return &geantJudge{t: t, in: in, out: sc}
}

func (g *geantJudge) ask(op string, args ...string) string {
	g.t.Helper()
	line := op
	for _, a := range args {
		line += "\t" + hex.EncodeToString([]byte(a))
	}
	if _, err := io.WriteString(g.in, line+"\n"); err != nil {
		g.t.Fatal(err)
	}
	if !g.out.Scan() {
		g.t.Fatalf("the judge did not answer %s: %v", op, g.out.Err())
	}
	return g.out.Text()
}

func (g *geantJudge) match(p, h string) bool { return g.ask("match", p, h) == "true" }

// globMatch reads pattern with '*' as [^.]+ (rep "+", the specification)
// or [^.]* (rep "*", what GÉANT's path.Match-based matcher implements),
// with or without regard to case.
func globMatch(pattern, host string, fold bool, rep string) bool {
	var b strings.Builder
	if fold {
		b.WriteString(`(?i)`)
	}
	b.WriteString(`\A`)
	for i, part := range strings.Split(pattern, "*") {
		if i > 0 {
			b.WriteString(`[^.]` + rep)
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String()).MatchString(host)
}

// matchCorpus: the specification's examples and cases, then pairs built
// from labels chosen to meet at the edges (empty matches, case, several
// wildcards, label counts), then random strings over an alphabet holding
// the characters a shell-style matcher reads as syntax.
func matchCorpus() [][2]string {
	var c [][2]string
	for _, m := range matchCases {
		c = append(c, [2]string{m.pattern, m.host})
	}
	r := rand.New(rand.NewPCG(1, 2))
	plabels := []string{"*", "a", "A", "ab", "*b", "a*", "*-*", "prod-*", "a*b*c", "**", "?", "[ab]", `\*`, "", "x"}
	hlabels := []string{"a", "A", "ab", "b", "aXbYc", "abc", "prod-", "prod-1", "a-b", "-", "", "x", "*", "?"}
	pick := func(ls []string, n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = ls[r.IntN(len(ls))]
		}
		return strings.Join(parts, ".")
	}
	for range 30000 {
		n := 1 + r.IntN(3)
		m := n
		if r.IntN(4) == 0 {
			m = 1 + r.IntN(3)
		}
		c = append(c, [2]string{pick(plabels, n) + ".org", pick(hlabels, m) + ".org"})
	}
	const alphabet = "aAb-.*?[]\\^!"
	str := func() string {
		b := make([]byte, r.IntN(9))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		return string(b)
	}
	for range 30000 {
		c = append(c, [2]string{str(), str()})
	}
	return c
}

// TestGEANTJudgeMatch compares MatchDomain with GÉANT's cert.MatchDomain.
// The categories of divergence, and why this package is right in each:
//
//   - empty-star: GÉANT's '*' also matches no characters ("prod-*.x" matches
//     "prod-.x"); the specification says "one or more characters".
//   - case: GÉANT compares case-sensitively; DNS names are case-insensitive
//     (RFC 4343), and the specification compares domain names.
//   - invalid: GÉANT matches a pattern or host this package refuses (shell
//     syntax '?', '[...]' and '\' that path.Match reads, empty labels, a
//     wildcard in the rightmost label, a host containing '*'...); the
//     specification defines '*' as the only wildcard and requires
//     implementations to "reject malformed domain names".
func TestGEANTJudgeMatch(t *testing.T) {
	g := newGEANTJudge(t)
	count := map[string]int{}
	example := map[string][2]string{}
	agree := 0
	corpus := matchCorpus()
	for _, c := range corpus {
		p, h := c[0], c[1]
		ours, theirs := MatchDomain(p, h), g.match(p, h)
		if ours == theirs {
			agree++
			continue
		}
		var cat string
		valid := ValidatePattern(p) == nil && validateName(h, false) == nil
		switch {
		case !valid:
			if theirs {
				cat = "invalid"
			}
		case theirs != globMatch(p, h, false, "*"):
			// GÉANT is not doing what this test's model of it says.
		case globMatch(p, h, false, "+") != globMatch(p, h, false, "*"):
			cat = "empty-star"
		case ours == globMatch(p, h, true, "+") && theirs == globMatch(p, h, false, "+"):
			cat = "case"
		}
		if cat == "" {
			t.Errorf("unexplained divergence on (%q, %q): ours %v, GÉANT's %v", p, h, ours, theirs)
			continue
		}
		count[cat]++
		if _, ok := example[cat]; !ok {
			example[cat] = c
		}
	}
	cats := make([]string, 0, len(count))
	for k := range count {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	t.Logf("%d pairs: %d agree", len(corpus), agree)
	for _, k := range cats {
		e := example[k]
		t.Logf("  %-10s %6d  e.g. pattern %q host %q: GÉANT %v, ours %v", k, count[k], e[0], e[1], g.match(e[0], e[1]), MatchDomain(e[0], e[1]))
	}
	for _, k := range []string{"empty-star", "case", "invalid"} {
		if count[k] == 0 {
			t.Errorf("no %s divergence found: the corpus no longer reaches it", k)
		}
	}
}

// TestGEANTJudgeParse: for each extension value, what GÉANT's parser
// extracts and whether GÉANT's ssh-cert-authorize would let the
// certificate in on login.example.org (its authorize.go: no domains
// extracted means "might be valid for non-domain-based auth", and the
// certificate goes on to the principals), against this package's answer.
// Every value this package refuses and GÉANT reads as "no domains" is a
// fail-open: a certificate whose grant is malformed is accepted on every
// host.
func TestGEANTJudgeParse(t *testing.T) {
	g := newGEANTJudge(t)
	ca := testSigner(t)
	const host = "login.example.org"
	values := []string{
		`["login.example.org"]`, `["*.example.org"]`, `["other.example.com"]`, `[]`,
		`null`, `{}`, `{"a":"login.example.org"}`, `[1]`, `[null]`, `"login.example.org"`,
		`["login.example.org"] `, ` ["login.example.org"]`, `["login.example.org", "x.org"]`,
		`["login.example.org"]x`, `["login.example.org"`, `[""]`, `["*"]`, `["*.*"]`,
		`["LOGIN.example.org"]`, `["login.example.org","login.example.org"]`,
		"[\"login\\u002eexample.org\"]",
	}
	failOpen := 0
	for _, v := range values {
		c := signedCert(t, ca, map[string]string{DomainGrantExtension: v})
		got := g.ask("cert", string(c.Marshal()))
		var domains []string
		theirsIn := false
		switch got {
		case "error":
			t.Fatalf("%s: GÉANT could not parse the certificate", v)
		case "none":
			theirsIn = true // authorize.go: no domains, falls through
		default:
			j, _ := hex.DecodeString(got)
			domains = strings.Split(strings.Trim(string(j), `[]`), ",")
			for i := range domains {
				domains[i] = strings.Trim(domains[i], `"`)
			}
			for _, d := range domains {
				if g.match(d, host) {
					theirsIn = true
				}
			}
		}
		p, _, err := DomainGrant(c)
		oursIn := err == nil && Grants(p, host)
		verdict := ""
		switch {
		case theirsIn && !oursIn && got == "none":
			verdict = "GÉANT FAIL-OPEN (no domains read: accepted on every host)"
			failOpen++
		case theirsIn && !oursIn:
			verdict = "GÉANT accepts, ours refuses"
		case !theirsIn && oursIn:
			verdict = "ours accepts, GÉANT refuses"
		}
		ourRead := fmt.Sprintf("%q", p)
		if err != nil {
			ourRead = "refused"
		}
		t.Logf("%-48q GÉANT reads %-8s in=%-5v | ours %-24s in=%-5v %s", v, shortHex(got), theirsIn, ourRead, oursIn, verdict)
		if oursIn && !theirsIn && !strings.EqualFold(v, `["LOGIN.example.org"]`) {
			t.Errorf("%s: this package accepts what GÉANT refuses", v)
		}
	}
	if failOpen == 0 {
		t.Error("no fail-open found: GÉANT's parser changed, revisit the README")
	}
	t.Logf("%d of %d values are a fail-open in GÉANT's ssh-cert-authorize", failOpen, len(values))
}

func shortHex(s string) string {
	if s == "none" || s == "error" {
		return s
	}
	b, _ := hex.DecodeString(s)
	return string(b)
}
