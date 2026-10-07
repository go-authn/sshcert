// SPDX-License-Identifier: BSD-3-Clause

package main

import "os"

// exit is os.Exit, replaced by the tests.
var exit = os.Exit

func main() {
	exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
