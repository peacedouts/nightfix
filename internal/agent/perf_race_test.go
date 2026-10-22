//go:build race

package agent

// perfBudgetScale stretches wall-clock budgets in performance tests: the race
// detector makes this code several times slower.
const perfBudgetScale = 8
