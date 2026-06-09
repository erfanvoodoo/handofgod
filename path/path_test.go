package path

import (
	"testing"
	"time"
)

func TestMultipathSelection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DuplicationCount = 3
	e := NewEngine(cfg)
	e.BuildPaths(
		[]string{"8.8.8.8:53", "1.1.1.1:53"},
		[]string{"a.example.com", "b.example.com"},
		cfg,
	)
	// 2 resolvers × 2 domains = 4 paths
	if got := len(e.AllStats()); got != 4 {
		t.Fatalf("path count: got %d want 4", got)
	}

	selected := e.SelectPaths()
	if len(selected) != 3 {
		t.Fatalf("selected %d want 3 (duplication count)", len(selected))
	}
}

func TestUnhealthyPathExcluded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DuplicationCount = 4
	e := NewEngine(cfg)
	paths := []*Path{}
	for _, r := range []string{"r1", "r2", "r3", "r4"} {
		paths = append(paths, e.AddPath(r, "d", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput))
	}

	// Fail one path past the health limit
	for i := 0; i < cfg.HealthFailLimit; i++ {
		paths[0].MarkProbeFail(cfg.HealthFailLimit)
	}

	if e.HealthyCount() != 3 {
		t.Errorf("healthy count: got %d want 3", e.HealthyCount())
	}
	// SelectPaths should now only return 3 even though duplication is 4
	if got := len(e.SelectPaths()); got != 3 {
		t.Errorf("selected %d want 3 (one unhealthy)", got)
	}

	// Recovery
	paths[0].MarkProbeOK()
	if e.HealthyCount() != 4 {
		t.Errorf("after recovery healthy count: got %d want 4", e.HealthyCount())
	}
}

func TestScoringPrefersLowLoss(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DuplicationCount = 1
	e := NewEngine(cfg)
	good := e.AddPath("good", "d", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
	bad := e.AddPath("bad", "d", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)

	// Good path: all successes. Bad path: all failures (but not enough to mark unhealthy)
	for i := 0; i < 5; i++ {
		good.RecordResult(true)
	}
	bad.RecordResult(false)
	bad.RecordResult(true) // keep it healthy but with high loss

	selected := e.SelectPaths()
	if len(selected) != 1 || selected[0].Resolver != "good" {
		t.Errorf("expected 'good' path selected, got %+v", selected)
	}
}

func TestMTUTracking(t *testing.T) {
	cfg := DefaultConfig()
	e := NewEngine(cfg)
	p1 := e.AddPath("r1", "d", 0.5, 0.3, 0.2)
	p2 := e.AddPath("r2", "d", 0.5, 0.3, 0.2)
	p1.SetMTU(180)
	p2.SetMTU(120)

	if e.SmallestMTU() != 120 {
		t.Errorf("smallest MTU: got %d want 120", e.SmallestMTU())
	}
}

func TestRecordResultFailoverAndRecovery(t *testing.T) {
	cfg := DefaultConfig() // HealthFailLimit = 3
	e := NewEngine(cfg)
	p := e.AddPath("r", "d", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)

	// Below the limit: still healthy.
	for i := 0; i < cfg.HealthFailLimit-1; i++ {
		p.RecordResult(false)
	}
	if e.HealthyCount() != 1 {
		t.Fatalf("path should still be healthy before the limit, healthy=%d", e.HealthyCount())
	}

	// Hitting the limit excludes it and makes it a recovery candidate.
	p.RecordResult(false)
	if e.HealthyCount() != 0 {
		t.Fatalf("path should be unhealthy at the fail limit, healthy=%d", e.HealthyCount())
	}
	if len(e.SelectPaths()) != 0 {
		t.Error("unhealthy path must be excluded from SelectPaths")
	}
	if rc := e.RecoveryCandidates(); len(rc) != 1 || rc[0] != p {
		t.Fatalf("unhealthy path should be the recovery candidate, got %d", len(rc))
	}

	// A success recovers it.
	p.RecordResult(true)
	if e.HealthyCount() != 1 {
		t.Errorf("path should recover after a success, healthy=%d", e.HealthyCount())
	}
	if len(e.RecoveryCandidates()) != 0 {
		t.Error("recovered path should not be a recovery candidate")
	}
}

func TestIntermittentLossStaysHealthy(t *testing.T) {
	cfg := DefaultConfig()
	e := NewEngine(cfg)
	p := e.AddPath("r", "d", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
	// Failures interspersed with successes never reach the consecutive limit.
	for i := 0; i < 10; i++ {
		p.RecordResult(false)
		p.RecordResult(false)
		p.RecordResult(true)
	}
	if e.HealthyCount() != 1 {
		t.Errorf("intermittent loss should not exclude a path, healthy=%d", e.HealthyCount())
	}
}

func TestRTTPercentiles(t *testing.T) {
	p := newPath("r", "d", 0.5, 0.3, 0.2, 3)
	// Record exactly maxSamples (64) values so the ring buffer holds all of them.
	for i := 1; i <= 64; i++ {
		p.RecordRTT(time.Duration(i) * time.Millisecond)
	}
	stats := p.Stats()
	// With samples 1..64ms: p50 ≈ 32ms (index int(0.5*63)=31 → 32ms),
	// p95 ≈ 60ms (index int(0.95*63)=59 → 60ms).
	if stats.RTTp50 < 28*time.Millisecond || stats.RTTp50 > 36*time.Millisecond {
		t.Errorf("p50 out of range: %v", stats.RTTp50)
	}
	if stats.RTTp95 < 56*time.Millisecond || stats.RTTp95 > 64*time.Millisecond {
		t.Errorf("p95 out of range: %v", stats.RTTp95)
	}
}
