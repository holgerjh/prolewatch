package brief

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestArchiveProbeProductionSandboxContract(t *testing.T) {
	args := archiveProbeBwrapArgs()
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" --unshare-all ", " --disable-userns --assert-userns-disabled ", " --ro-bind-fd 3 /input ", " --clearenv ", " /usr/bin/bsdtar -tf /input "} {
		if !strings.Contains(joined, required) {
			t.Fatalf("archive probe sandbox is missing %q: %v", required, args)
		}
	}
	if strings.Contains(joined, " --share-net ") || strings.Contains(joined, " --bind ") {
		t.Fatalf("archive probe unexpectedly exposes network or writable paths: %v", args)
	}
}
func TestArchiveProbeResultClassificationWithoutNamespaces(t *testing.T) {
	if recognized, err := classifyArchiveProbeResult(nil, nil, 0, ""); err != nil || !recognized {
		t.Fatalf("successful bsdtar probe was not recognized: recognized=%t err=%v", recognized, err)
	}
	if recognized, err := classifyArchiveProbeResult(context.DeadlineExceeded, errors.New("killed"), -1, ""); recognized || err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout was misclassified: recognized=%t err=%v", recognized, err)
	}
	if recognized, err := classifyArchiveProbeResult(nil, errors.New("exit status 1"), 1, "bsdtar: Unrecognized archive format"); recognized || err != nil {
		t.Fatalf("ordinary non-archive was misclassified: recognized=%t err=%v", recognized, err)
	}
	if recognized, err := classifyArchiveProbeResult(nil, errors.New("permission denied"), -1, "bwrap: setting up uid map: Permission denied"); recognized || err == nil || !strings.Contains(err.Error(), "uid map") {
		t.Fatalf("sandbox failure was swallowed: recognized=%t err=%v", recognized, err)
	}
}
