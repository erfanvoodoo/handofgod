package dns

import (
	"time"

	"github.com/handofgod/path"
)

// pathbridge.go connects the path engine's live health to the adaptive
// controller. It is intentionally the only file in the dns package that imports
// a transport package: the core Client stays decoupled (UpdateConditions takes a
// plain Conditions), and this thin adapter maps path.Engine stats onto it.

// ConditionsFromEngine derives adaptive Conditions from the path engine's live
// per-path stats.
//
// It models the conditions the transport actually experiences. Because reliable
// frames are duplicated across the top healthy paths (§8.2), the best healthy
// path dominates delivery — so loss and RTT are taken from the best (lowest)
// healthy path rather than an average that a single bad path could skew. When
// paths are configured but none are healthy, that is reported as a blackout (the
// strongest escalation signal), which models a full outage or active filtering.
func ConditionsFromEngine(e *path.Engine) Conditions {
	stats := e.AllStats()
	if len(stats) == 0 {
		// Nothing configured yet — assume benign rather than fabricate a threat.
		return Conditions{}
	}

	haveHealthy := false
	bestLoss := 1.0
	var bestRTT time.Duration
	rttSet := false

	for _, s := range stats {
		if !s.Healthy {
			continue
		}
		haveHealthy = true
		if s.LossRate < bestLoss {
			bestLoss = s.LossRate
		}
		// Ignore paths with no RTT sample yet (RTTp50 == 0) so they don't peg
		// the representative RTT at zero before any probe lands.
		if s.RTTp50 > 0 && (!rttSet || s.RTTp50 < bestRTT) {
			bestRTT = s.RTTp50
			rttSet = true
		}
	}

	if !haveHealthy {
		return Conditions{LossRate: 1.0, Blackout: true}
	}
	return Conditions{LossRate: bestLoss, RTT: bestRTT}
}

// ObserveEngine folds the engine's current health into the adaptive controller
// and applies the resulting profile to the scheduler. It is the path-driven
// equivalent of UpdateConditions; the transport calls it periodically (e.g. on
// each health-probe cycle) so stealth posture tracks real path conditions.
func (c *Client) ObserveEngine(e *path.Engine) *Profile {
	return c.UpdateConditions(ConditionsFromEngine(e))
}
