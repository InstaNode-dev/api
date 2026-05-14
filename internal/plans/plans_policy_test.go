package plans_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonplans "instant.dev/common/plans"
	"instant.dev/internal/plans"
)

// TestPolicy_NoTrialPayDayOne enforces the "no trial — pay from day one"
// policy by scanning plans.yaml for any `trial_days` field and failing if
// found. Anonymous is the ONLY free tier (24h TTL); hobby/pro/team are
// paid from signup. There is no free trial on any paid plan.
//
// If you are tempted to re-introduce trial_days, talk to the founder first.
// See project memory note `project_no_trial_pay_day_one.md`.
func TestPolicy_NoTrialPayDayOne(t *testing.T) {
	// Walk up from this test file to find plans.yaml in the api repo root.
	// Tests run from internal/plans/, so plans.yaml is two levels up.
	candidates := []string{
		filepath.Join("..", "..", "plans.yaml"),
		"plans.yaml",
	}

	var (
		data []byte
		err  error
		path string
	)
	for _, c := range candidates {
		data, err = os.ReadFile(c)
		if err == nil {
			path = c
			break
		}
	}
	require.NoError(t, err, "plans.yaml must exist (looked in %v)", candidates)

	if bytes.Contains(data, []byte("trial_days")) {
		t.Fatalf(
			"%s contains the string 'trial_days' — this violates the "+
				"'no trial, pay from day one' policy. Anonymous (24h TTL) "+
				"is the only free tier; hobby/pro/team are paid from signup. "+
				"Remove every trial_days entry.",
			path,
		)
	}
}

// TestPolicy_NoTrialDaysMethodOnRegistry uses reflection to assert that the
// re-exported Registry type does not expose a TrialDays method. If someone
// re-adds the helper, this test will fail and force a re-review of the
// policy. Same intent as the YAML scanner above — belt-and-suspenders.
func TestPolicy_NoTrialDaysMethodOnRegistry(t *testing.T) {
	r := plans.Default()
	rt := reflect.TypeOf(r)
	_, found := rt.MethodByName("TrialDays")
	assert.False(t, found,
		"plans.Registry must not expose a TrialDays method — see "+
			"TestPolicy_NoTrialPayDayOne for the underlying policy")
}

// TestPolicy_NoTrialDaysFieldOnPlan ensures that the common.Plan struct
// itself has no TrialDays field. Removed on 2026-05-13 alongside the
// `trial_days` YAML keys. If someone re-adds the field, this test fails.
func TestPolicy_NoTrialDaysFieldOnPlan(t *testing.T) {
	var p commonplans.Plan
	rt := reflect.TypeOf(p)
	_, found := rt.FieldByName("TrialDays")
	assert.False(t, found,
		"commonplans.Plan must not expose a TrialDays field — see "+
			"TestPolicy_NoTrialPayDayOne for the underlying policy")
}
