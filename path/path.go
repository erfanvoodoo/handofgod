// Package path implements Hand of God's path engine: resolver scoring, per-path MTU
// tracking, health checks, and multi-path scheduling with duplication.
// See PROTOCOL.md §7 and §8.
package path

import (
	"sort"
	"sync"
	"time"
)

// Path represents one (resolver, domain) tuple over which frames travel.
type Path struct {
	Resolver string // e.g. "8.8.8.8:53"
	Domain   string // e.g. "v.example.com"

	mu sync.Mutex

	// Loss tracking (EWMA)
	lossRate float64

	// Latency tracking (moving samples for percentiles)
	rttSamples []time.Duration
	maxSamples int

	// Throughput
	bytesDelivered uint64
	since          time.Time

	// MTU discovered for this path (payload bytes)
	mtu int

	// Health
	consecutiveFails int
	healthy          bool
	failLimit        int // consecutive failures before the path is marked unhealthy

	// Scoring weights (copied from engine)
	wLoss, wLat, wTput float64
}

// PathStats is a snapshot of a path's health for observability.
type PathStats struct {
	Resolver       string
	Domain         string
	LossRate       float64
	RTTp50         time.Duration
	RTTp95         time.Duration
	MTU            int
	Healthy        bool
	Score          float64
	BytesDelivered uint64
}

func newPath(resolver, domain string, wLoss, wLat, wTput float64, failLimit int) *Path {
	if failLimit < 1 {
		failLimit = 3
	}
	return &Path{
		Resolver:   resolver,
		Domain:     domain,
		maxSamples: 64,
		mtu:        40, // conservative default until probed
		healthy:    true,
		failLimit:  failLimit,
		since:      time.Now(),
		wLoss:      wLoss,
		wLat:       wLat,
		wTput:      wTput,
	}
}

// RecordResult updates loss EWMA based on whether a send succeeded, and drives
// health/failover: a success restores the path; failLimit consecutive failures
// (with no intervening success) mark it unhealthy so SelectPaths excludes it.
// Recovery happens when a later probe/response succeeds (see Engine.RecoveryCandidates).
func (p *Path) RecordResult(success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	const alpha = 0.1
	sample := 1.0
	if success {
		sample = 0.0
	}
	p.lossRate = (1-alpha)*p.lossRate + alpha*sample

	if success {
		p.consecutiveFails = 0
		p.healthy = true
	} else {
		p.consecutiveFails++
		if p.consecutiveFails >= p.failLimit {
			p.healthy = false
		}
	}
}

// RecordRTT adds an RTT sample (ring buffer of recent samples).
func (p *Path) RecordRTT(rtt time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rttSamples = append(p.rttSamples, rtt)
	if len(p.rttSamples) > p.maxSamples {
		p.rttSamples = p.rttSamples[1:]
	}
}

// RecordDelivered adds to throughput accounting.
func (p *Path) RecordDelivered(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytesDelivered += uint64(n)
}

// SetMTU records a discovered MTU for this path.
func (p *Path) SetMTU(mtu int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if mtu > 0 {
		p.mtu = mtu
	}
}

// MTU returns the path's current MTU.
func (p *Path) MTU() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mtu
}

// MarkProbeFail increments the health failure counter; marks unhealthy past the limit.
func (p *Path) MarkProbeFail(limit int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consecutiveFails++
	if p.consecutiveFails >= limit {
		p.healthy = false
	}
}

// MarkProbeOK resets the failure counter and restores health.
func (p *Path) MarkProbeOK() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consecutiveFails = 0
	p.healthy = true
}

// score computes the path's current desirability (higher is better).
// Acquires p.mu; do not call while already holding p.mu — use scoreLocked.
func (p *Path) score() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scoreLocked()
}

// scoreLocked is score() without locking; caller must hold p.mu.
func (p *Path) scoreLocked() float64 {
	if !p.healthy {
		return -1
	}

	lossFactor := 1.0 - p.lossRate

	// Latency factor: lower p50 → higher factor. Normalize against 2s reference.
	latFactor := 1.0
	if len(p.rttSamples) > 0 {
		p50 := p.percentileLocked(0.50)
		latFactor = 1.0 - clampFloat(float64(p50)/float64(2*time.Second), 0, 1)
	}

	// Throughput factor: bytes/sec normalized against a 4KB/s reference.
	elapsed := time.Since(p.since).Seconds()
	tputFactor := 0.0
	if elapsed > 0 {
		bps := float64(p.bytesDelivered) / elapsed
		tputFactor = clampFloat(bps/4096.0, 0, 1)
	}

	return p.wLoss*lossFactor + p.wLat*latFactor + p.wTput*tputFactor
}

func (p *Path) percentileLocked(pct float64) time.Duration {
	if len(p.rttSamples) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(p.rttSamples))
	copy(sorted, p.rttSamples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(pct * float64(len(sorted)-1))
	return sorted[idx]
}

// Stats returns a consistent snapshot of this path's state.
func (p *Path) Stats() PathStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PathStats{
		Resolver:       p.Resolver,
		Domain:         p.Domain,
		LossRate:       p.lossRate,
		RTTp50:         p.percentileLocked(0.50),
		RTTp95:         p.percentileLocked(0.95),
		MTU:            p.mtu,
		Healthy:        p.healthy,
		Score:          p.scoreLocked(),
		BytesDelivered: p.bytesDelivered,
	}
}

// ── Engine ────────────────────────────────────────────────────────────────────

// Engine manages the pool of paths and schedules multi-path transmission.
type Engine struct {
	mu               sync.RWMutex
	paths            []*Path
	duplicationCount int
	healthFailLimit  int
}

// Config configures the path engine.
type Config struct {
	DuplicationCount int     // how many paths to send each frame on
	HealthFailLimit  int     // consecutive probe failures before marking unhealthy
	WeightLoss       float64 // scoring weight for loss
	WeightLatency    float64 // scoring weight for latency
	WeightThroughput float64 // scoring weight for throughput
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		DuplicationCount: 3,
		HealthFailLimit:  3,
		WeightLoss:       0.5,
		WeightLatency:    0.3,
		WeightThroughput: 0.2,
	}
}

// NewEngine creates a path engine.
func NewEngine(cfg Config) *Engine {
	if cfg.DuplicationCount < 1 {
		cfg.DuplicationCount = 1
	}
	if cfg.HealthFailLimit < 1 {
		cfg.HealthFailLimit = 3
	}
	return &Engine{
		duplicationCount: cfg.DuplicationCount,
		healthFailLimit:  cfg.HealthFailLimit,
	}
}

// AddPath registers a (resolver, domain) path. Call BuildPaths for combinations.
func (e *Engine) AddPath(resolver, domain string, wLoss, wLat, wTput float64) *Path {
	p := newPath(resolver, domain, wLoss, wLat, wTput, e.healthFailLimit)
	e.mu.Lock()
	e.paths = append(e.paths, p)
	e.mu.Unlock()
	return p
}

// BuildPaths creates the full cross-product of resolvers × domains.
// This is how N resolvers and M domains become N×M independent paths.
func (e *Engine) BuildPaths(resolvers, domains []string, cfg Config) {
	for _, r := range resolvers {
		for _, d := range domains {
			e.AddPath(r, d, cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
		}
	}
}

// SelectPaths returns the top-K healthy paths by score for transmitting a frame.
// K is the duplication count. Returns fewer if not enough healthy paths exist.
func (e *Engine) SelectPaths() []*Path {
	e.mu.RLock()
	defer e.mu.RUnlock()

	type scored struct {
		p     *Path
		score float64
	}
	candidates := make([]scored, 0, len(e.paths))
	for _, p := range e.paths {
		s := p.score()
		if s < 0 {
			continue // unhealthy
		}
		candidates = append(candidates, scored{p, s})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })

	k := e.duplicationCount
	if k > len(candidates) {
		k = len(candidates)
	}
	out := make([]*Path, k)
	for i := 0; i < k; i++ {
		out[i] = candidates[i].p
	}
	return out
}

// HealthyCount returns the number of currently healthy paths.
func (e *Engine) HealthyCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, p := range e.paths {
		if p.score() >= 0 {
			n++
		}
	}
	return n
}

// RecoveryCandidates returns the currently unhealthy paths — those excluded from
// SelectPaths. The transport probes these directly (bypassing top-K selection)
// so a recovered path can re-prove itself and rejoin (PROTOCOL.md §8.3).
func (e *Engine) RecoveryCandidates() []*Path {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []*Path
	for _, p := range e.paths {
		if p.score() < 0 {
			out = append(out, p)
		}
	}
	return out
}

// AllStats returns stats for every path, for observability.
func (e *Engine) AllStats() []PathStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]PathStats, 0, len(e.paths))
	for _, p := range e.paths {
		out = append(out, p.Stats())
	}
	return out
}

// SmallestMTU returns the smallest MTU among healthy paths, which bounds the
// frame size that can be reliably duplicated across the selected paths.
func (e *Engine) SmallestMTU() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	min := 0
	for _, p := range e.paths {
		if p.score() < 0 {
			continue
		}
		m := p.MTU()
		if min == 0 || m < min {
			min = m
		}
	}
	if min == 0 {
		return 40
	}
	return min
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
