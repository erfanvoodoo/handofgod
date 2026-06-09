package dns

import (
	"testing"
	"time"
)

func TestAdaptiveStartsStandard(t *testing.T) {
	a := NewAdaptiveController(DefaultAdaptiveConfig())
	if a.Level() != LevelStandard {
		t.Errorf("start level: got %v want standard", a.Level())
	}
	if a.Current() != &ProfileStandardDNS {
		t.Error("default profile should be standard_dns")
	}
}

func TestAdaptiveEscalatesImmediately(t *testing.T) {
	a := NewAdaptiveController(DefaultAdaptiveConfig())

	// Blackout is the strongest signal — jump straight to Max.
	if p := a.Observe(Conditions{Blackout: true}); p != &ProfileHighStealth {
		t.Errorf("blackout should select high_stealth, got %v", a.Level())
	}
	if a.Level() != LevelMax {
		t.Errorf("blackout level: got %v want max", a.Level())
	}
}

func TestAdaptiveElevatesOnLossAndRTT(t *testing.T) {
	a := NewAdaptiveController(DefaultAdaptiveConfig())
	if p := a.Observe(Conditions{LossRate: 0.20}); p != &ProfileDoHMix {
		t.Errorf("loss 0.20 should select doh_mix, got %v", a.Level())
	}

	b := NewAdaptiveController(DefaultAdaptiveConfig())
	b.Observe(Conditions{RTT: time.Second})
	if b.Level() != LevelElevated {
		t.Errorf("high RTT should elevate, got %v", b.Level())
	}
}

func TestAdaptiveMaxOnHighLoss(t *testing.T) {
	a := NewAdaptiveController(DefaultAdaptiveConfig())
	a.Observe(Conditions{LossRate: 0.60})
	if a.Level() != LevelMax {
		t.Errorf("loss 0.60 should select max, got %v", a.Level())
	}
}

// TestAdaptiveDowngradeHysteresis verifies de-escalation requires sustained
// good samples and steps down one level at a time.
func TestAdaptiveDowngradeHysteresis(t *testing.T) {
	cfg := DefaultAdaptiveConfig()
	cfg.DowngradeRuns = 3
	a := NewAdaptiveController(cfg)

	a.Observe(Conditions{Blackout: true})
	if a.Level() != LevelMax {
		t.Fatalf("expected Max after blackout, got %v", a.Level())
	}

	good := Conditions{LossRate: 0.0, RTT: 50 * time.Millisecond}

	// Not enough good samples to relax.
	a.Observe(good)
	a.Observe(good)
	if a.Level() != LevelMax {
		t.Errorf("after 2 good samples: got %v want still Max", a.Level())
	}
	// Third good sample steps down exactly one level.
	a.Observe(good)
	if a.Level() != LevelElevated {
		t.Errorf("after 3 good samples: got %v want Elevated", a.Level())
	}
	// Three more relax to Standard.
	a.Observe(good)
	a.Observe(good)
	a.Observe(good)
	if a.Level() != LevelStandard {
		t.Errorf("after sustained good: got %v want Standard", a.Level())
	}
}

// TestAdaptiveReEscalationResetsStreak verifies a threat sample wipes accumulated
// downgrade progress.
func TestAdaptiveReEscalationResetsStreak(t *testing.T) {
	cfg := DefaultAdaptiveConfig()
	cfg.DowngradeRuns = 3
	a := NewAdaptiveController(cfg)

	a.Observe(Conditions{Blackout: true}) // Max
	a.Observe(Conditions{})               // streak 1
	a.Observe(Conditions{})               // streak 2
	a.Observe(Conditions{Blackout: true}) // re-escalate, streak reset
	if a.Level() != LevelMax {
		t.Fatalf("expected Max after re-escalation, got %v", a.Level())
	}
	a.Observe(Conditions{}) // streak 1
	a.Observe(Conditions{}) // streak 2
	if a.Level() != LevelMax {
		t.Errorf("streak should have reset; got %v want still Max", a.Level())
	}
}

func TestAdaptiveSetProfile(t *testing.T) {
	a := NewAdaptiveController(DefaultAdaptiveConfig())
	custom := &Profile{Name: "custom_max"}
	a.SetProfile(LevelMax, custom)
	if p := a.Observe(Conditions{Blackout: true}); p != custom {
		t.Errorf("expected custom max profile, got %v", p.Name)
	}
}
