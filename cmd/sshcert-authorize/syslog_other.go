// SPDX-License-Identifier: BSD-3-Clause

//go:build windows || plan9

package main

import "errors"

// dialSyslog fails where there is no syslog: the command then refuses
// every certificate until it is run with --syslog=false.
var dialSyslog = func(string) (syslogWriter, error) {
	return nil, errors.New("syslog is not available on this platform; use --syslog=false")
}
