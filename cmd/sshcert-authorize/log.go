// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"strconv"
)

// syslogWriter is the part of *log/syslog.Writer the logger uses.
type syslogWriter interface {
	Debug(string) error
	Info(string) error
	Warning(string) error
	Err(string) error
	Close() error
}

// logger writes key=value lines to syslog, or to stderr with
// --syslog=false. With --debug it also writes everything to stderr, as
// GÉANT's tool does, and logs debug lines.
type logger struct {
	sys   syslogWriter
	err   io.Writer
	debug bool
}

func newLogger(useSyslog, debug bool, stderr io.Writer) (*logger, error) {
	l := &logger{err: stderr, debug: debug}
	if useSyslog {
		w, err := dialSyslog("sshcert-authorize")
		if err != nil {
			return nil, fmt.Errorf("syslog: %w", err)
		}
		l.sys = w
	}
	return l, nil
}

func (l *logger) close() {
	if l.sys != nil {
		l.sys.Close()
	}
}

func (l *logger) emit(level, format string, args []any) {
	msg := fmt.Sprintf(format, args...)
	if l.sys != nil {
		// A lost log line is not a reason to refuse or accept.
		switch level {
		case "DEBUG":
			l.sys.Debug(msg)
		case "INFO":
			l.sys.Info(msg)
		case "WARNING":
			l.sys.Warning(msg)
		default:
			l.sys.Err(msg)
		}
	}
	if l.sys == nil || l.debug {
		fmt.Fprintf(l.err, "%s: %s\n", level, msg)
	}
}

func (l *logger) infof(format string, args ...any)    { l.emit("INFO", format, args) }
func (l *logger) warningf(format string, args ...any) { l.emit("WARNING", format, args) }
func (l *logger) errorf(format string, args ...any)   { l.emit("ERROR", format, args) }

func (l *logger) debugf(format string, args ...any) {
	if l.debug {
		l.emit("DEBUG", format, args)
	}
}

// kv formats a value for a key=value log line: as is when it is made of
// characters that cannot break the line's structure, quoted otherwise.
// The user name comes from the client, so a value never carries a raw
// space, '=', newline or control character into the log.
func kv(v string) string {
	if v == "" {
		return `""`
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= ' ' || c >= 0x7f || c == '=' || c == '\\' || (c == '"' && v[0] != '[') {
			return strconv.QuoteToASCII(v)
		}
	}
	return v
}
