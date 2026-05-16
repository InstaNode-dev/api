package handlers

// ExportedPlanIDToTier exposes the unexported planIDToTier resolver to
// the external _test package so the new yearly plan-id mapping can be
// asserted without making the helper itself public. Only included in the
// test binary thanks to the _test.go suffix.
func ExportedPlanIDToTier(h *BillingHandler, planID string) string {
	return h.planIDToTier(planID)
}

// PlanIDToTierFallbackForTest exposes the planIDToTierFallback constant
// to the external handlers_test package so regression tests assert the
// safe-fallback tier rather than hard-coding "hobby". If the constant
// changes in future the tests automatically track it.
const PlanIDToTierFallbackForTest = planIDToTierFallback
