package mobile

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func endpointIDs(points []endpoint) string {
	ids := make([]string, 0, len(points))
	for _, p := range points {
		ids = append(ids, p.ID)
	}
	return strings.Join(ids, " ")
}

// historyClock replaces the wall clock with one the test moves by hand.
func historyClock(t *testing.T) *atomic.Int64 {
	t.Helper()
	var offset atomic.Int64
	previous := wallNow
	wallNow = func() time.Time { return time.Now().Round(0).Add(time.Duration(offset.Load())) }
	t.Cleanup(func() { wallNow = previous })
	return &offset
}

func TestAdaptiveAttemptOrder(t *testing.T) {
	points := []endpoint{
		{ID: "udp", Kind: "hysteria2"},
		{ID: "cdn", Kind: cdnEndpointKind},
		{ID: "reality", Kind: "vless_reality"},
		{ID: "relay", Kind: "vless_reality"},
		{ID: "cdn2", Kind: cdnEndpointKind},
	}
	engine := func(adaptive, whitelist bool, preferred string) *Engine {
		return &Engine{config: mobileConfig{Endpoints: points, PreferredEndpoint: preferred, AdaptiveEndpoints: adaptive, WhitelistMode: whitelist}}
	}
	order := func(e *Engine, first string) string { return endpointIDs(e.attemptOrder(e.config, first)) }
	t.Run("off", func(t *testing.T) {
		e := engine(false, false, "reality")
		e.history.startFailed("udp", wallNow())
		e.history.ended("relay", wallNow().Add(-time.Minute), wallNow(), true)
		if got := order(e, "relay"); got != "relay reality udp" {
			t.Fatalf("Order without adaptive endpoints = %q", got)
		}
		e.activeID = "relay"
		if got := e.TryBetter(); got != "" {
			t.Fatalf("TryBetter without adaptive endpoints = %q", got)
		}
		whitelist := engine(false, true, "")
		if got := order(whitelist, "cdn2"); got != "cdn2 cdn" {
			t.Fatalf("Whitelist order without adaptive endpoints = %q", got)
		}
	})
	t.Run("no-history", func(t *testing.T) {
		if got := order(engine(true, false, "reality"), "relay"); got != "relay reality udp cdn cdn2" {
			t.Fatalf("Order without history = %q", got)
		}
		// A healthy CDN fallback is never first, even when it was the last good endpoint.
		if got := order(engine(true, false, "cdn2"), "cdn"); got != "udp reality relay cdn cdn2" {
			t.Fatalf("Order after a CDN run = %q", got)
		}
		if got := order(engine(true, true, "cdn2"), "cdn"); got != "cdn cdn2" {
			t.Fatalf("Whitelist order = %q", got)
		}
	})
	t.Run("penalty", func(t *testing.T) {
		clock := historyClock(t)
		e := engine(true, false, "")
		now := wallNow()
		e.history.ended("relay", now.Add(-9*time.Minute), now, true)
		if got := order(e, "relay"); got != "udp reality cdn cdn2 relay" {
			t.Fatalf("Order after a short run = %q", got)
		}
		clock.Add(int64(penaltyBase))
		if got := order(e, "relay"); got != "relay udp reality cdn cdn2" {
			t.Fatalf("Order after the penalty = %q", got)
		}
	})
	t.Run("stable-run", func(t *testing.T) {
		e := engine(true, false, "")
		now := wallNow()
		e.history.ended("relay", now.Add(-stableUptime), now, true)
		if got := order(e, "relay"); got != "relay udp reality cdn cdn2" {
			t.Fatalf("Order after a stable run = %q", got)
		}
		// Leaving an endpoint on purpose is not a drop.
		e.history.ended("udp", now.Add(-time.Minute), now, false)
		if got := order(e, "udp"); got != "udp reality relay cdn cdn2" {
			t.Fatalf("Order after a planned switch = %q", got)
		}
	})
	t.Run("penalty-growth", func(t *testing.T) {
		clock := historyClock(t)
		e := engine(true, false, "")
		for strike, want := range []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute, 160 * time.Minute, 320 * time.Minute, 6 * time.Hour, 6 * time.Hour} {
			now := wallNow()
			e.history.ended("relay", now.Add(-time.Minute), now, true)
			entries := e.history.entries(now)
			if len(entries) != 1 || entries[0].Strikes != strike+1 || entries[0].PenaltyUntil != now.Add(want).Unix() {
				t.Fatalf("Strike %d = %+v, want a penalty of %v", strike+1, entries, want)
			}
			clock.Add(int64(time.Minute))
		}
		now := wallNow()
		e.history.ended("relay", now.Add(-stableUptime), now, true)
		if entries := e.history.entries(now); len(entries) != 0 {
			t.Fatalf("History after a stable run = %+v", entries)
		}
		e.history.ended("relay", now.Add(-time.Minute), now, true)
		if entries := e.history.entries(now); len(entries) != 1 || entries[0].PenaltyUntil != now.Add(penaltyBase).Unix() {
			t.Fatalf("First strike after a reset = %+v", entries)
		}
	})
	t.Run("start-failure", func(t *testing.T) {
		clock := historyClock(t)
		e := engine(true, false, "")
		e.history.startFailed("udp", wallNow())
		if got := order(e, ""); got != "reality relay cdn cdn2 udp" {
			t.Fatalf("Order after a failed start = %q", got)
		}
		clock.Add(int64(startFailMemory - time.Second))
		if got := order(e, ""); got != "reality relay cdn cdn2 udp" {
			t.Fatalf("Order just before the memory ends = %q", got)
		}
		clock.Add(int64(time.Second))
		if got := order(e, ""); got != "udp reality relay cdn cdn2" {
			t.Fatalf("Order after the memory ends = %q", got)
		}
		e.history.startFailed("udp", wallNow())
		e.history.started("udp")
		if got := order(e, ""); got != "udp reality relay cdn cdn2" {
			t.Fatalf("Order after a later successful start = %q", got)
		}
	})
	t.Run("all-unhealthy", func(t *testing.T) {
		clock := historyClock(t)
		e := engine(true, false, "udp")
		for _, id := range []string{"cdn2", "relay", "udp", "cdn", "reality"} {
			e.history.startFailed(id, wallNow())
			clock.Add(int64(time.Second))
		}
		if got := order(e, "reality"); got != "cdn2 relay udp cdn reality" {
			t.Fatalf("Order with every endpoint unhealthy = %q", got)
		}
	})
	t.Run("better-candidates", func(t *testing.T) {
		e := engine(true, false, "")
		better := func(active string) string { return endpointIDs(e.betterCandidates(e.config, active, wallNow())) }
		for active, want := range map[string]string{"udp": "", "reality": "udp", "relay": "udp reality", "cdn": "udp reality relay", "cdn2": "udp reality relay", "unknown": ""} {
			if got := better(active); got != want {
				t.Fatalf("Better than %q = %q, want %q", active, got, want)
			}
		}
		e.history.startFailed("udp", wallNow())
		e.history.ended("reality", wallNow().Add(-time.Minute), wallNow(), true)
		if got := better("cdn"); got != "relay" {
			t.Fatalf("Better than cdn with unhealthy endpoints = %q", got)
		}
		whitelist := engine(true, true, "")
		if got := endpointIDs(whitelist.betterCandidates(whitelist.config, "cdn2", wallNow())); got != "cdn" {
			t.Fatalf("Better than cdn2 in whitelist mode = %q", got)
		}
	})
	t.Run("report-and-reset", func(t *testing.T) {
		e := engine(true, false, "")
		now := wallNow()
		e.history.startFailed("udp", now)
		e.history.ended("relay", now.Add(-time.Minute), now, true)
		var entries []endpointHistoryEntry
		decoder := json.NewDecoder(strings.NewReader(e.EndpointHistory()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entries); err != nil {
			t.Fatal(err)
		}
		want := []endpointHistoryEntry{{ID: "relay", PenaltyUntil: now.Add(penaltyBase).Unix(), Strikes: 1}, {ID: "udp", StartFailedAt: now.Unix()}}
		if len(entries) != 2 || entries[0] != want[0] || entries[1] != want[1] {
			t.Fatalf("EndpointHistory = %+v, want %+v", entries, want)
		}
		e.activeSince = now
		e.ResetEndpointHistory()
		if got := order(e, "relay"); got != "relay udp reality cdn cdn2" || e.EndpointHistory() != "[]" || !e.activeSince.IsZero() {
			t.Fatalf("After a reset: order %q, history %s, active since %v", got, e.EndpointHistory(), e.activeSince)
		}
	})
}

// near allows for the seconds a local handshake takes after the engine read the clock.
func near(unix int64, want time.Time) bool {
	return unix <= want.Unix() && unix >= want.Unix()-5
}

func TestAdaptiveReconnectAndTryBetter(t *testing.T) {
	localTransportProbe(t)
	clock := historyClock(t)
	// Each server rejects the ticket while its switch is off.
	var down [3]atomic.Bool
	points := make([]endpoint, 3)
	for i, id := range []string{"a", "b", "c"} {
		points[i], _ = localHysteriaServer(t, func(auth string) bool { return auth == "legacy-ticket" && !down[i].Load() })
		points[i].ID = id
	}
	e := newTestEngine(t, "ALL")
	e.platform = &transportTestPlatform{}
	e.config.Endpoints, e.config.AdaptiveEndpoints = points, true
	if err := e.connect(""); err != nil || e.ActiveEndpoint() != "a" {
		t.Fatalf("Connect = %q, %v", e.ActiveEndpoint(), err)
	}
	if got := e.TryBetter(); got != "" {
		t.Fatalf("TryBetter on the first endpoint = %q", got)
	}

	// A drop after a stable run starts again with the same endpoint.
	clock.Add(int64(stableUptime))
	if err := e.Reconnect(); err != nil || e.ActiveEndpoint() != "a" || e.EndpointHistory() != "[]" {
		t.Fatalf("Reconnect after a stable run = %q, %v, history %s", e.ActiveEndpoint(), err, e.EndpointHistory())
	}

	// A drop soon after the start moves on and penalises the endpoint.
	clock.Add(int64(time.Minute))
	if err := e.Reconnect(); err != nil || e.ActiveEndpoint() != "b" {
		t.Fatalf("Reconnect after a short run = %q, %v", e.ActiveEndpoint(), err)
	}
	if got := e.TryBetter(); got != "" || e.ActiveEndpoint() != "b" {
		t.Fatalf("TryBetter under a penalty = %q, active %q", got, e.ActiveEndpoint())
	}

	// A second short run doubles the penalty.
	clock.Add(int64(penaltyBase))
	if got := e.TryBetter(); got != "a" || e.ActiveEndpoint() != "a" {
		t.Fatalf("TryBetter after the penalty = %q, active %q", got, e.ActiveEndpoint())
	}
	clock.Add(int64(time.Minute))
	if err := e.Reconnect(); err != nil || e.ActiveEndpoint() != "b" {
		t.Fatalf("Reconnect after the second short run = %q, %v", e.ActiveEndpoint(), err)
	}
	var entries []endpointHistoryEntry
	if err := json.Unmarshal([]byte(e.EndpointHistory()), &entries); err != nil || len(entries) != 1 || entries[0].ID != "a" || entries[0].Strikes != 2 || !near(entries[0].PenaltyUntil, wallNow().Add(2*penaltyBase)) {
		t.Fatalf("History after two short runs = %s, %v", e.EndpointHistory(), err)
	}

	// A failed probe keeps the active endpoint and is remembered.
	clock.Add(int64(2 * penaltyBase))
	down[0].Store(true)
	if got := e.TryBetter(); got != "" || e.ActiveEndpoint() != "b" {
		t.Fatalf("TryBetter with a failing endpoint = %q, active %q", got, e.ActiveEndpoint())
	}
	if err := json.Unmarshal([]byte(e.EndpointHistory()), &entries); err != nil || len(entries) != 1 || !near(entries[0].StartFailedAt, wallNow()) {
		t.Fatalf("History after a failed probe = %s, %v", e.EndpointHistory(), err)
	}
	down[0].Store(false)
	if got := e.TryBetter(); got != "" {
		t.Fatalf("TryBetter within the failed start's memory = %q", got)
	}

	// With every endpoint unhealthy, a reconnect still tries them all.
	down[1].Store(true)
	down[2].Store(true)
	clock.Add(int64(time.Minute))
	if err := e.Reconnect(); err != nil || e.ActiveEndpoint() != "a" {
		t.Fatalf("Reconnect with the others down = %q, %v", e.ActiveEndpoint(), err)
	}

	// A network change forgets the history and the run of the active endpoint.
	e.ResetEndpointHistory()
	down[1].Store(false)
	if err := e.Reconnect(); err != nil || e.ActiveEndpoint() != "a" || e.EndpointHistory() != "[]" {
		t.Fatalf("Reconnect after a reset = %q, %v, history %s", e.ActiveEndpoint(), err, e.EndpointHistory())
	}
}

func TestAdaptiveEndpointsConcurrency(t *testing.T) {
	localTransportProbe(t)
	points := make([]endpoint, 2)
	for i, id := range []string{"a", "b"} {
		points[i], _ = localHysteriaEndpoint(t)
		points[i].ID = id
	}
	e := newTestEngine(t, "ALL")
	e.platform = &transportTestPlatform{}
	e.config.Endpoints, e.config.AdaptiveEndpoints = points, true
	if err := e.connect("b"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, work := range []func(){
		func() { _ = e.Reconnect() },
		func() { _ = e.TryBetter() },
		func() { _ = e.TrySwitch("a") },
		func() { _ = e.TrySwitch("b") },
		func() { _ = e.EndpointHistory(); e.ResetEndpointHistory() },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				work()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = e.Close()
	}()
	wg.Wait()
	if got := e.TryBetter(); got != "" {
		t.Fatalf("TryBetter after Close = %q", got)
	}
}
