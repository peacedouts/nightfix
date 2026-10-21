//go:build race

package expr

import "time"

// The race detector slows evaluation several-fold, so the time between
// interrupt checks (and the overshoot past the deadline) grows with it.
const raceSlack = 2 * time.Second
