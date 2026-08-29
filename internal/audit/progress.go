package audit

import (
	"context"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/egress"
)

// Stages name the security work shown on the transaction's live progress line.
const (
	StageInitializing       = "initializing"
	StageAIProviderCheck    = "ai-provider-check"
	StageArchiveParserCheck = "archive-parser-check"
	StagePolicyFingerprint  = "policy-fingerprint"
	StageAIProviderIdentity = "ai-provider-identity"
	StageAIProviderAttest   = "ai-provider-attestation"
	StageMarkerVerification = "decision-marker-verification"
	StageSourcePlanFreeze   = "source-plan-freeze"
	StageSourceAcquisition  = "source-acquisition"
	StageDeterministicScan  = "deterministic-scan"
	StageAIReview           = "ai-review"
	StageBubblewrapLaunch   = "bubblewrap-launch"
	StageSandboxExecution   = "sandbox-execution"
	StagePostDownloadRescan = "post-download-rescan"
	StageArtifactInspection = "artifact-inspection"
	StageArtifactBinding    = "artifact-binding"
	StageComplete           = "complete"
)

func progressStage(ctx context.Context, stage string) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.Stage(stage, 0)
	}
}

func progressTimedStage(ctx context.Context, stage string, timeoutSeconds int) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.Stage(stage, timeoutSeconds)
	}
}

func progressAI(ctx context.Context, batch, count, timeoutSeconds int, trigger string) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.AI(batch, count, timeoutSeconds, trigger)
	}
}

func progressScan(ctx context.Context, scan brief.ScanProgress) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.Scan(scan)
	}
}

func progressAcquisition(ctx context.Context, transfer egress.AcquisitionProgress) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.Source(transfer.Filename, transfer.SourceIndex, transfer.SourceCount, transfer.Bytes, transfer.Total, transfer.BytesPerSecond, transfer.Complete)
	}
}

func progressActivity(ctx context.Context, activity string) {
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.SetActivity(activity)
	}
}
