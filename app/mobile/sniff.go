// Copyright (c) 2026 ChromVoid LLC. SPDX-License-Identifier: MIT
package mobile

import (
	"net"
	"time"

	"github.com/apernet/hysteria/extras/v2/sniff"
	"github.com/apernet/quic-go"
)

// sniffDestination uses the upstream MIT classifier and preserves all consumed bytes.
func sniffDestination(conn net.Conn) ([]byte, string) {
	address := "0.0.0.0:443"
	classifier := sniff.Sniffer{Timeout: 250 * time.Millisecond}
	payload, _ := classifier.TCP(streamAdapter{Conn: conn}, &address)
	host, _, _ := net.SplitHostPort(address)
	if net.ParseIP(host) != nil {
		host = ""
	}
	return payload, normalizedDomain(host)
}

type streamAdapter struct{ net.Conn }

func (streamAdapter) StreamID() quic.StreamID { return 0 }

type udpSniff struct {
	packets [][]byte
	bytes   int
	timer   *time.Timer
}

// sniffUDP is called with sendMu held. Only the first bounded QUIC flight is buffered.
func (u *routedUDP) sniffUDP(data []byte, original, address string) error {
	if direct, exists := u.udpDecisions[original]; exists {
		return u.sendClassified(data, original, address, direct)
	}
	if len(u.udpDecisions)+len(u.sniffing) >= 64 && u.sniffing[original] == nil {
		return u.sendClassified(data, original, address, false)
	}
	state := u.sniffing[original]
	if state == nil {
		state = &udpSniff{}
		u.sniffing[original] = state
		state.timer = time.AfterFunc(250*time.Millisecond, func() {
			u.sendMu.Lock()
			defer u.sendMu.Unlock()
			if u.ctx.Err() == nil && u.sniffing[original] == state {
				_ = u.flushSniff(original, address, false)
			}
		})
	}
	state.packets = append(state.packets, append([]byte(nil), data...))
	state.bytes += len(data)
	request := address
	classifier := sniff.Sniffer{}
	complete, _ := classifier.UDP(state.packets, &request)
	if complete || state.bytes >= 65536 {
		host, _, _ := net.SplitHostPort(request)
		return u.flushSniff(original, address, russianDomain(host))
	}
	return nil
}

func (u *routedUDP) flushSniff(original, address string, direct bool) error {
	state := u.sniffing[original]
	if state == nil {
		return nil
	}
	state.timer.Stop()
	delete(u.sniffing, original)
	u.udpDecisions[original] = direct
	for _, packet := range state.packets {
		if err := u.sendClassified(packet, original, address, direct); err != nil {
			return err
		}
	}
	return nil
}

func (u *routedUDP) sendClassified(data []byte, original, address string, direct bool) error {
	if direct {
		return u.sendDirect(data, original, address)
	}
	hy, err := u.proxySession()
	if err != nil {
		return err
	}
	return hy.Send(data, address)
}
