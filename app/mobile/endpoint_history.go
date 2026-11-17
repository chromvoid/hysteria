package mobile

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// An endpoint that drops before stableUptime is penalised for penaltyBase,
// doubling with each drop in a row up to penaltyMax. The numbers match the
// node penalties of the Wayveil Go client.
const (
	stableUptime    = 10 * time.Minute
	penaltyBase     = 10 * time.Minute
	penaltyMax      = 6 * time.Hour
	startFailMemory = 10 * time.Minute
	cdnEndpointKind = "vless_xhttp_cdn"
)

type endpointRecord struct {
	strikes      int
	penalizedAt  time.Time
	penaltyUntil time.Time
	failedAt     time.Time
}

// endpointHistory remembers, per endpoint ID and for one Engine, which
// endpoints dropped soon after they came up and which failed to start.
type endpointHistory struct {
	mu      sync.Mutex
	records map[string]*endpointRecord
}

// penalized reports whether the penalty is running. One that starts after
// now, left by a clock that went back, is not.
func (r *endpointRecord) penalized(now time.Time) bool {
	return r.penaltyUntil.After(now) && !now.Before(r.penalizedAt)
}

// remembersFailure reports whether the failed start still counts. One dated
// after now, left by a clock that went back, does not.
func (r *endpointRecord) remembersFailure(now time.Time) bool {
	return !r.failedAt.IsZero() && !now.Before(r.failedAt) && now.Sub(r.failedAt) < startFailMemory
}

func (h *endpointHistory) record(id string) *endpointRecord {
	if h.records == nil {
		h.records = make(map[string]*endpointRecord)
	}
	r := h.records[id]
	if r == nil {
		r = &endpointRecord{}
		h.records[id] = r
	}
	return r
}

// startFailed notes a failed attempt to bring the endpoint up.
func (h *endpointHistory) startFailed(id string, now time.Time) {
	if id == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.record(id).failedAt = now
}

// started forgets the endpoint's failed start: it has just passed the probe.
func (h *endpointHistory) started(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r := h.records[id]; r != nil {
		r.failedAt = time.Time{}
	}
}

// ended closes a run of the endpoint that began at since. A run of
// stableUptime or longer clears its penalties; a shorter one that ended in a
// drop adds a penalty.
func (h *endpointHistory) ended(id string, since, now time.Time, dropped bool) {
	// A clock that went back leaves the length of the run unknown.
	if id == "" || since.IsZero() || now.Before(since) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if now.Sub(since) >= stableUptime {
		if r := h.records[id]; r != nil {
			r.strikes, r.penalizedAt, r.penaltyUntil = 0, time.Time{}, time.Time{}
		}
		return
	}
	if !dropped {
		return
	}
	r := h.record(id)
	// Strikes count drops in a row: one long after the last penalty starts over.
	if r.strikes > 0 && now.Sub(r.penaltyUntil) > penaltyMax {
		r.strikes = 0
	}
	r.strikes++
	penalty := penaltyMax
	// 6 h is under 10 min << 6, so larger shifts never need computing.
	if r.strikes <= 6 {
		penalty = min(penaltyBase<<(r.strikes-1), penaltyMax)
	}
	r.penalizedAt, r.penaltyUntil = now, now.Add(penalty)
}

// unhealthySince reports the latest moment the endpoint failed, if a penalty
// is still running or a failed start is still remembered.
func (h *endpointHistory) unhealthySince(id string, now time.Time) (time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.records[id]
	if r == nil {
		return time.Time{}, false
	}
	var at time.Time
	if r.penalized(now) {
		at = r.penalizedAt
	}
	if r.remembersFailure(now) && r.failedAt.After(at) {
		at = r.failedAt
	}
	return at, !at.IsZero()
}

func (h *endpointHistory) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = nil
}

type endpointHistoryEntry struct {
	ID            string `json:"id"`
	PenaltyUntil  int64  `json:"penalty_until"`
	Strikes       int    `json:"strikes"`
	StartFailedAt int64  `json:"start_failed_at"`
}

func (h *endpointHistory) entries(now time.Time) []endpointHistoryEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	entries := make([]endpointHistoryEntry, 0, len(h.records))
	for id, r := range h.records {
		entry := endpointHistoryEntry{ID: id, Strikes: r.strikes}
		if r.penalized(now) {
			entry.PenaltyUntil = r.penaltyUntil.Unix()
		}
		if r.remembersFailure(now) {
			entry.StartFailedAt = r.failedAt.Unix()
		}
		if entry.PenaltyUntil != 0 || entry.Strikes != 0 || entry.StartFailedAt != 0 {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

// usablePoints are the endpoints a connection may use. Without adaptive
// endpoints the CDN endpoints are used only in whitelist mode, and nothing
// else is used there. With them, CDN endpoints also stay outside whitelist
// mode, as the last fallback.
func usablePoints(config mobileConfig) []endpoint {
	points := make([]endpoint, 0, len(config.Endpoints))
	for _, p := range config.Endpoints {
		cdn := p.Kind == cdnEndpointKind
		if cdn == config.WhitelistMode || (cdn && config.AdaptiveEndpoints) {
			points = append(points, p)
		}
	}
	return points
}

// isFallback reports whether the endpoint is tried only after the healthy
// ordinary ones: a CDN endpoint outside whitelist mode.
func isFallback(config mobileConfig, p endpoint) bool {
	return p.Kind == cdnEndpointKind && !config.WhitelistMode
}

// attemptOrder is the order in which connect tries the endpoints: first, the
// preferred one, then the rest as configured. With adaptive endpoints that
// order holds for the healthy ordinary endpoints; healthy CDN fallbacks
// follow, and endpoints with a running penalty or a recent failed start come
// last, the oldest failure first. No usable endpoint is left out.
func (e *Engine) attemptOrder(config mobileConfig, first string) []endpoint {
	points := usablePoints(config)
	ordered := make([]endpoint, 0, len(points))
	for _, p := range points {
		if p.ID == first {
			ordered = append(ordered, p)
		}
	}
	for _, p := range points {
		if p.ID == config.PreferredEndpoint && p.ID != first {
			ordered = append(ordered, p)
		}
	}
	for _, p := range points {
		if p.ID != first && p.ID != config.PreferredEndpoint {
			ordered = append(ordered, p)
		}
	}
	if !config.AdaptiveEndpoints {
		return ordered
	}
	// The clock is read only here: without adaptive endpoints connect reads it exactly as before.
	now := wallNow()
	type failed struct {
		point endpoint
		at    time.Time
	}
	healthy := make([]endpoint, 0, len(ordered))
	var fallbacks []endpoint
	var unhealthy []failed
	for _, p := range ordered {
		if at, bad := e.history.unhealthySince(p.ID, now); bad {
			unhealthy = append(unhealthy, failed{p, at})
		} else if isFallback(config, p) {
			fallbacks = append(fallbacks, p)
		} else {
			healthy = append(healthy, p)
		}
	}
	// Fallbacks keep the configured order, not the first/preferred one.
	sort.SliceStable(fallbacks, func(i, j int) bool {
		return pointIndex(points, fallbacks[i].ID) < pointIndex(points, fallbacks[j].ID)
	})
	sort.SliceStable(unhealthy, func(i, j int) bool { return unhealthy[i].at.Before(unhealthy[j].at) })
	healthy = append(healthy, fallbacks...)
	for _, f := range unhealthy {
		healthy = append(healthy, f.point)
	}
	return healthy
}

func pointIndex(points []endpoint, id string) int {
	for i, p := range points {
		if p.ID == id {
			return i
		}
	}
	return -1
}

// TryBetter moves a live connection to a healthy endpoint that is configured
// ahead of the active one, without interrupting traffic: the old transport
// carries it until the new one passes the probe. From a CDN fallback every
// ordinary endpoint counts as ahead. Endpoints of skipKind are left out: a
// client that returns to Hysteria2 on its own schedule passes "hysteria2".
// It returns the ID of the endpoint it moved to, or an empty string. It does
// nothing without adaptive endpoints.
func (e *Engine) TryBetter(skipKind string) string {
	if !e.switching.CompareAndSwap(false, true) {
		return ""
	}
	defer e.switching.Store(false)
	e.mu.RLock()
	closed, active, gen, config := e.closed, e.activeID, e.generation.Load(), e.config
	e.mu.RUnlock()
	if closed || active == "" || !config.AdaptiveEndpoints {
		return ""
	}
	candidates := e.betterCandidates(config, active, skipKind, wallNow())
	if len(candidates) == 0 {
		return ""
	}
	budget := min(max(time.Duration(len(candidates))*endpointTimeout, connectTimeout), maxConnectTimeout)
	deadline := wallNow().Add(budget)
	ctx, cancel := context.WithTimeout(e.ctx, budget)
	defer cancel()
	for _, p := range candidates {
		if ctx.Err() != nil || !wallNow().Before(deadline) {
			return ""
		}
		transport, ok := e.probeCandidate(ctx, p, min(endpointTimeout, deadline.Sub(wallNow())), true)
		if !ok {
			continue
		}
		// A lost race with Reconnect or Close ends the pass: the generation is stale.
		if e.promote(transport, p.ID, gen, true) {
			return p.ID
		}
		return ""
	}
	return ""
}

// betterCandidates are the healthy endpoints configured ahead of the active
// one, in the configured order. Ahead of an ordinary endpoint are the ordinary
// ones before it; ahead of a CDN fallback is every ordinary endpoint.
func (e *Engine) betterCandidates(config mobileConfig, active, skipKind string, now time.Time) []endpoint {
	points := usablePoints(config)
	index := pointIndex(points, active)
	if index < 0 {
		return nil
	}
	fromFallback := isFallback(config, points[index])
	var candidates []endpoint
	for i, p := range points {
		if p.ID == active || p.Kind == skipKind || isFallback(config, p) || (!fromFallback && i > index) {
			continue
		}
		if _, bad := e.history.unhealthySince(p.ID, now); !bad {
			candidates = append(candidates, p)
		}
	}
	return candidates
}

// probeCandidate brings an endpoint up beside the active transport and runs
// the data transfer check through it.
func (e *Engine) probeCandidate(parent context.Context, p endpoint, timeout time.Duration, adaptive bool) (vpnTransport, bool) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	transport, err := e.newTransport(context.WithValue(ctx, probeTransportKey{}, true), p)
	if err == nil {
		err = probeEndpoint(ctx, transport)
	}
	cancel()
	if err == nil {
		return transport, true
	}
	if transport != nil {
		_ = transport.Close()
	}
	if adaptive && e.ctx.Err() == nil {
		e.history.startFailed(p.ID, wallNow())
	}
	return nil, false
}

// ResetEndpointHistory forgets every penalty and failed start. Clients call it
// when the network changes: the history describes the previous network. The
// current run of the active endpoint is no longer judged either, so the
// reconnect that follows the change is not counted against it.
func (e *Engine) ResetEndpointHistory() {
	e.mu.Lock()
	e.activeSince = time.Time{}
	e.mu.Unlock()
	e.history.reset()
}

// EndpointHistory returns a JSON array of the endpoints with a running
// penalty, strikes or a remembered failed start: id, penalty_until and
// start_failed_at in Unix seconds (0 when absent) and strikes.
func (e *Engine) EndpointHistory() string {
	now := wallNow()
	e.mu.RLock()
	active, since := e.activeID, e.activeSince
	e.mu.RUnlock()
	// A run that is already stable has cleared the endpoint; do not wait for its end to show it.
	if active != "" && !since.IsZero() && now.Sub(since) >= stableUptime {
		e.history.ended(active, since, now, false)
	}
	encoded, _ := json.Marshal(e.history.entries(now))
	return string(encoded)
}
