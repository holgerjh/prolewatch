package audit

// Stable process statuses form the protocol between yay, the wrappers, and
// Prolewatch. Keep meanings here so callers do not have to infer policy from
// otherwise unexplained integers.
const (
	ExitOK                = 0
	ExitPolicyBlock       = 10
	ExitInvalidInvocation = 20
	ExitInspectionFailure = 21
	ExitReviewUnavailable = 22
	ExitStateFailure      = 23
	ExitExecutionFailure  = 24
	ExitArtifactFailure   = 25
)
