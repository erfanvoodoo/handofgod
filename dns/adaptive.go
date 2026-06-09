package dns

import (
	"sync"
	"time"
)

// adaptive.go implements Hand of God's Phase 3 traffic shaping for constrained and
// hostile environments: a controller that escalates and de-escalates the active
// stealth profile in response to observed path conditions.
//
// The principle is "cheap until threatened": run the throughput-friendly
// standard profile while the network behaves, escalate quickly toward maximum
// stealth when loss spikes or responses stop entirely (a signature of active
// filtering), and step back down only cautiously (hysteresis) so a single good
// sample does not yank the session out of a stealth posture it still needs.
//
// The controller is deliberately decoupled from the transport: callers feed it
// Conditions sampled from the path engine / metrics, and it returns the Profile
// to drive the encoder and scheduler. This keeps the dns package free of
// transport imports (integration wiring is Phase 4).

// StealthLevel is the escalating shaping posture selected by the controller.
type StealthLevel int

const (
	// LevelStandard is the throughput-friendly baseline (standard_dns).
	LevelStandard StealthLevel = iota
	// LevelElevated adds cover and larger records for lossy/slow paths (doh_mix).
	LevelElevated
	// LevelMax is maximum stealth for suspected active filtering (high_stealth).
	LevelMax
)

// String returns the level mnemonic.
func (l StealthLevel) String() string {
	switch l {
	case LevelStandard:
		return "standard"
	case LevelElevated:
		return "elevated"
	case LevelMax:
		return "max"
	default:
		return "unknown"
	}
}

// Conditions is a snapshot of observed path health fed to the controller.
type Conditions struct {
	// LossRate is the aggregate path loss EWMA in [0,1].
	LossRate float64
	// RTT is a representative round-trip time (e.g. best-path p50).
	RTT time.Duration
	// Blackout is true when no responses have arrived in a probe window — the
	// strongest signal of active filtering or a full outage.
	Blackout bool
}

// AdaptiveConfig tunes the escalation thresholds and downgrade hysteresis.
type AdaptiveConfig struct {
	// ElevateLoss: loss at or above this escalates to at least Elevated.
	ElevateLoss float64
	// MaxLoss: loss at or above this escalates straight to Max.
	MaxLoss float64
	// ElevateRTT: RTT at or above this escalates to at least Elevated (0 disables).
	ElevateRTT time.Duration
	// DowngradeRuns: consecutive observations in a lower band required to step
	// down one level. Escalation is always immediate.
	DowngradeRuns int
}

// DefaultAdaptiveConfig returns sensible thresholds for DNS-latency paths.
func DefaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		ElevateLoss:   0.15,
		MaxLoss:       0.50,
		ElevateRTT:    800 * time.Millisecond,
		DowngradeRuns: 5,
	}
}

// AdaptiveController selects a stealth profile from observed conditions, with
// fast escalation and hysteretic de-escalation. Safe for concurrent use.
type AdaptiveController struct {
	mu          sync.Mutex
	cfg         AdaptiveConfig
	level       StealthLevel
	lowerStreak int
	profiles    map[StealthLevel]*Profile
}

// NewAdaptiveController creates a controller starting at LevelStandard, mapping
// each level to its built-in profile.
func NewAdaptiveController(cfg AdaptiveConfig) *AdaptiveController {
	if cfg.DowngradeRuns < 1 {
		cfg.DowngradeRuns = 1
	}
	return &AdaptiveController{
		cfg:   cfg,
		level: LevelStandard,
		profiles: map[StealthLevel]*Profile{
			LevelStandard: &ProfileStandardDNS,
			LevelElevated: &ProfileDoHMix,
			LevelMax:      &ProfileHighStealth,
		},
	}
}

// SetProfile overrides the profile used for a level (e.g. an operator-tuned
// variant loaded from JSON).
func (a *AdaptiveController) SetProfile(level StealthLevel, p *Profile) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.profiles[level] = p
}

// Observe folds in a new conditions sample and returns the profile to use now.
// Escalation toward more stealth is immediate; de-escalation requires
// DowngradeRuns consecutive lower-band samples per level (hysteresis).
func (a *AdaptiveController) Observe(c Conditions) *Profile {
	a.mu.Lock()
	defer a.mu.Unlock()

	target := a.targetLevel(c)
	switch {
	case target > a.level:
		// Threat rising: jump straight to the indicated level.
		a.level = target
		a.lowerStreak = 0
	case target < a.level:
		// Conditions look better: only relax after sustained good samples,
		// and only one level at a time.
		a.lowerStreak++
		if a.lowerStreak >= a.cfg.DowngradeRuns {
			a.level--
			a.lowerStreak = 0
		}
	default:
		a.lowerStreak = 0
	}
	return a.profiles[a.level]
}

// targetLevel maps a single conditions sample to the level it argues for.
func (a *AdaptiveController) targetLevel(c Conditions) StealthLevel {
	if c.Blackout || c.LossRate >= a.cfg.MaxLoss {
		return LevelMax
	}
	if c.LossRate >= a.cfg.ElevateLoss ||
		(a.cfg.ElevateRTT > 0 && c.RTT >= a.cfg.ElevateRTT) {
		return LevelElevated
	}
	return LevelStandard
}

// Level returns the current stealth level.
func (a *AdaptiveController) Level() StealthLevel {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.level
}

// Current returns the profile for the current level without folding in a sample.
func (a *AdaptiveController) Current() *Profile {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.profiles[a.level]
}
