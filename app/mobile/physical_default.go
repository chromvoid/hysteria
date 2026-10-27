// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
//go:build !ios

package mobile

import (
	"context"
	"net"
)

func physicalIPs(ctx context.Context, ip net.IP) ([]net.IPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []net.IPAddr{{IP: ip}}, nil
}
