// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"sync"
	_ "unsafe"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

// This diagnostic intentionally depends on the pinned Xray fork's internals.
// The key mirrors dialerConf; older pins have different layouts, so only len is safe.
//
//go:linkname xhttpDialerMap github.com/xtls/xray-core/transport/internet/splithttp.globalDialerMap
var xhttpDialerMap map[struct {
	xnet.Destination
	*internet.MemoryStreamConfig
}]*splithttp.XmuxManager

//go:linkname xhttpDialerAccess github.com/xtls/xray-core/transport/internet/splithttp.globalDialerAccess
var xhttpDialerAccess sync.Mutex

func xhttpDialerCount() int {
	xhttpDialerAccess.Lock()
	defer xhttpDialerAccess.Unlock()
	return len(xhttpDialerMap)
}
