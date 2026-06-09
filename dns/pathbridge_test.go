package dns

import (
	"testing"
	"time"

	"github.com/handofgod/path"
)

func addPath(e *path.Engine, cfg path.Config, resolver string) *path.Path {
	return e.AddPath(resolver, "v.example.com", cfg.WeightLoss, cfg.WeightLatency, cfg.WeightThroughput)
}

func TestConditionsFromEngine_Empty(t *testing.T) {
	e := path.NewEngine(path.DefaultConfig())
	c := ConditionsFromEngine(e)
	if c.Blackout || c.LossRate != 0 || c.RTT != 0 {
		t.Errorf("empty engine should be benign, got %+v", c)
	}
}

func TestConditionsFromEngine_Healthy(t *testing.T) {
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	p := addPath(e, cfg, "8.8.8.8:53")
	for i := 0; i < 10; i++ {
		p.RecordResult(true)
	}
	p.RecordRTT(120 * time.Millisecond)

	c := ConditionsFromEngine(e)
	if c.Blackout {
		t.Error("healthy path should not report blackout")
	}
	if c.LossRate > 0.001 {
		t.Errorf("loss: got %v want ~0", c.LossRate)
	}
	if c.RTT != 120*time.Millisecond {
		t.Errorf("rtt: got %v want 120ms", c.RTT)
	}
}

func TestConditionsFromEngine_Blackout(t *testing.T) {
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	p := addPath(e, cfg, "r1")
	for i := 0; i < cfg.HealthFailLimit; i++ {
		p.MarkProbeFail(cfg.HealthFailLimit)
	}

	c := ConditionsFromEngine(e)
	if !c.Blackout {
		t.Error("all-unhealthy engine should report blackout")
	}
	if c.LossRate != 1.0 {
		t.Errorf("loss: got %v want 1.0", c.LossRate)
	}
}

// TestConditionsFromEngine_BestPath confirms loss/RTT come from the best healthy
// path, not an average a single bad path could skew.
func TestConditionsFromEngine_BestPath(t *testing.T) {
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	clean := addPath(e, cfg, "clean")
	lossy := addPath(e, cfg, "lossy")

	for i := 0; i < 10; i++ {
		clean.RecordResult(true)  // loss stays ~0
		lossy.RecordResult(false) // loss EWMA climbs, but stays healthy
	}
	clean.RecordRTT(50 * time.Millisecond)
	lossy.RecordRTT(500 * time.Millisecond)

	c := ConditionsFromEngine(e)
	if c.LossRate > 0.001 {
		t.Errorf("best-path loss: got %v want ~0", c.LossRate)
	}
	if c.RTT != 50*time.Millisecond {
		t.Errorf("best-path rtt: got %v want 50ms", c.RTT)
	}
}

// TestClientObserveEngine confirms an all-unhealthy engine drives the client to
// maximum stealth through the full bridge.
func TestClientObserveEngine(t *testing.T) {
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	p := addPath(e, cfg, "r1")
	for i := 0; i < cfg.HealthFailLimit; i++ {
		p.MarkProbeFail(cfg.HealthFailLimit)
	}

	c := NewClient(ClientConfig{Zone: "v.example.com"})
	c.ObserveEngine(e)
	if st := c.Stats(); st.Level != "max" || st.Profile != "high_stealth" {
		t.Errorf("blackout engine should drive max/high_stealth, got %q/%q", st.Level, st.Profile)
	}
}

// TestClientObserveEngineRecovers confirms a healthy engine keeps the client at
// the standard posture.
func TestClientObserveEngineRecovers(t *testing.T) {
	cfg := path.DefaultConfig()
	e := path.NewEngine(cfg)
	p := addPath(e, cfg, "r1")
	for i := 0; i < 5; i++ {
		p.RecordResult(true)
	}
	p.RecordRTT(40 * time.Millisecond)

	c := NewClient(ClientConfig{Zone: "v.example.com"})
	c.ObserveEngine(e)
	if st := c.Stats(); st.Level != "standard" {
		t.Errorf("healthy engine should stay standard, got %q", st.Level)
	}
}
