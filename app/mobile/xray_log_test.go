// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"testing"

	xlog "github.com/xtls/xray-core/app/log"
	xseverity "github.com/xtls/xray-core/common/log"
)

// Xray's default log prints every connection with its destination; the tunnel must not write those to the journal.
func TestXrayLogsOnlyWarningsAndNoConnections(t *testing.T) {
	config := xrayLogConfig()
	if config.ErrorLogType != xlog.LogType_Console || config.ErrorLogLevel != xseverity.Severity_Warning {
		t.Fatal("Xray log is not limited to warnings on the console", config.ErrorLogType, config.ErrorLogLevel)
	}
	if config.AccessLogType != xlog.LogType_None || config.EnableDnsLog {
		t.Fatal("Xray logs connections or DNS queries", config.AccessLogType, config.EnableDnsLog)
	}
}
