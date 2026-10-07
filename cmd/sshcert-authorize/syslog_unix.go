// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package main

import "log/syslog"

// dialSyslog opens the system logger, facility AUTH, as GÉANT's
// ssh-cert-authorize does.
var dialSyslog = func(tag string) (syslogWriter, error) {
	return syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, tag)
}
