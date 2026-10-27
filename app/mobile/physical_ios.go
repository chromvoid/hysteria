// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
//go:build ios && cgo

package mobile

/*
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

static int physical_getaddrinfo(const char *host, struct addrinfo **result) {
	struct addrinfo hints = {0};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	// Darwin can synthesize NAT64 addresses even for numeric IPv4 destinations.
	hints.ai_flags = AI_DEFAULT;
	return getaddrinfo(host, NULL, &hints, result);
}
*/
import "C"

import (
	"context"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// Native getaddrinfo can outlive a canceled caller. Bound those outstanding
// calls while allowing the VPN's existing connection deadlines to return.
var physicalLookupSlots = make(chan struct{}, 4)

func physicalIPs(ctx context.Context, ip net.IP) ([]net.IPAddr, error) {
	select {
	case physicalLookupSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type lookupResult struct {
		addresses []net.IPAddr
		err       error
	}
	completed := make(chan lookupResult, 1)
	go func() {
		defer func() { <-physicalLookupSlots }()
		addresses, err := nativePhysicalIPs(ip)
		completed <- lookupResult{addresses, err}
	}()
	select {
	case result := <-completed:
		return result.addresses, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func nativePhysicalIPs(ip net.IP) ([]net.IPAddr, error) {
	host := C.CString(ip.String())
	defer C.free(unsafe.Pointer(host))
	var result *C.struct_addrinfo
	if C.physical_getaddrinfo(host, &result) != 0 {
		return nil, errors.New("Could not resolve the physical network address.")
	}
	defer C.freeaddrinfo(result)
	var addresses []net.IPAddr
	for current := result; current != nil; current = current.ai_next {
		var address net.IP
		switch current.ai_family {
		case C.AF_INET:
			raw := (*syscall.RawSockaddrInet4)(unsafe.Pointer(current.ai_addr))
			address = append(net.IP(nil), raw.Addr[:]...)
		case C.AF_INET6:
			raw := (*syscall.RawSockaddrInet6)(unsafe.Pointer(current.ai_addr))
			address = append(net.IP(nil), raw.Addr[:]...)
		default:
			continue
		}
		if ipv4 := address.To4(); ipv4 != nil {
			address = ipv4
		}
		addresses = append(addresses, net.IPAddr{IP: address})
	}
	if len(addresses) == 0 {
		return nil, errors.New("Could not resolve the physical network address.")
	}
	return addresses, nil
}
