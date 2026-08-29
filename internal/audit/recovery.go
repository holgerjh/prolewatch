package audit

import "strings"

// Structural failures are the one outcome with no interactive path: the
// transaction stops, and `prolewatch approve` refuses by design. Printing the
// stamp without a next step leaves a dead end, and a user who cannot tell a
// hostile package from a dirty checkout, a recipe defect, or a limit in
// Prolewatch itself reaches for the one lever that always works - removing the
// boundary. Guidance beside the failure is what keeps that from being the
// obvious move.
//
// So this text never names uninstall-hook. That escape hatch belongs to the
// makepkg compatibility stop, where the wrapper genuinely cannot proceed and
// the user has no other route; beside a suspicious package it would teach the
// wrong reflex. TestStructuralRecoveryNeverSuggestsDisablingTheHook binds that.
//
// It also never offers a way across. `sudo pacman -U` would install the archive
// as surely as an approval would, so naming it here would make the block a
// formality. Recovery is inspection, a clean rebuild, or an upstream report.

// recoveryClass is one diagnosed cause and what to do about it.
type recoveryClass struct {
	// title names what happened in the user's terms, not the rule's.
	title string
	// steps are ordered actions. Each one must be something the user can do
	// without crossing the boundary that just stopped them.
	steps []string
}

// escapeRules are decided from the bytes: a path leaves the tree, and no
// judgement about intent is involved.
var escapeRules = map[string]bool{
	"archive-escape":          true,
	"symlink-escape":          true,
	"source-reference-escape": true,
	"archive-depth-limit":     true,
}

// privilegeRules mark privilege the finished package would carry into the
// system on its own.
var privilegeRules = map[string]bool{
	"artifact-setid":      true,
	"artifact-capability": true,
	"mtree-privileged":    true,
}

// parseRules mark material that had to be read and could not be. The cause is
// genuinely ambiguous between a broken recipe and an input shape this release
// does not handle, so the guidance says both rather than picking one.
var parseRules = map[string]bool{
	"srcinfo-missing":             true,
	"extractable-source-missing":  true,
	"extractable-source-invalid":  true,
	"makepkg-archive-unsupported": true,
	"mandatory-control-invalid":   true,
	"shell-parse-incomplete":      true,
	"binary-header-invalid":       true,
}

// structuralRecovery diagnoses why a report could not be approved and returns
// the classes that apply, most specific first.
//
// It returns nothing for a report that is not a structural failure; the
// approvable path already has its own action line.
func structuralRecovery(report *Report) []recoveryClass {
	if report == nil || report.Decision != "block" || report.ApprovalEligible {
		return nil
	}
	var (
		classes                                             []recoveryClass
		toolDefect, escape, privilege, special, parse, race bool
	)
	for _, finding := range report.Findings {
		switch {
		case finding.RuleID == "threat-bundle-invalid":
			toolDefect = true
		case finding.Category == "archive_escape" || escapeRules[finding.RuleID]:
			escape = true
		case privilegeRules[finding.RuleID]:
			privilege = true
		case finding.RuleID == "special-file":
			special = true
		case parseRules[finding.RuleID]:
			parse = true
		}
		if strings.HasPrefix(finding.Rationale, "TOCTOU") {
			race = true
		}
	}

	// Prolewatch's own integrity comes first. If the tool could not validate
	// itself, nothing it says about the package was established, and sending
	// the user to inspect the recipe would be sending them after the wrong
	// thing entirely.
	if toolDefect {
		classes = append(classes, recoveryClass{
			title: "This is a Prolewatch defect, not a package defect.",
			steps: []string{
				"Prolewatch's embedded threat data failed its own validation, so no conclusion about this package was reached.",
				"Run prolewatch doctor, then reinstall Prolewatch from a verified package.",
				"No package can cause this. Report it with the report ID shown below.",
			},
		})
	}
	if escape {
		classes = append(classes, recoveryClass{
			title: "The package writes outside its own tree.",
			steps: []string{
				"The listed paths leave the package tree. This is decided from the bytes, so obfuscation does not change it and no approval crosses it.",
				"Inspect without extracting: bsdtar -tvf on the archive, or read the listed file in the AUR checkout.",
				"A working recipe does not need this. Report it to the AUR maintainer rather than building around it.",
			},
		})
	}
	if privilege {
		classes = append(classes, recoveryClass{
			title: "The finished package grants privilege on its own.",
			steps: []string{
				"A setuid or setgid entry, a file capability, or an mtree recording one was found in the built package.",
				"Some packages need this legitimately, and the bits alone cannot show which, so Prolewatch stops rather than guessing.",
				"Check whether upstream documents the requirement, and ask the AUR maintainer to state it in the recipe.",
			},
		})
	}
	if special {
		classes = append(classes, recoveryClass{
			title: "The tree contains files that are not valid package input.",
			steps: []string{
				"Device nodes, FIFOs, or sockets were found. These are usually a dirty build tree rather than a hostile recipe.",
				"Remove the cached AUR checkout together with its src/ and pkg/ directories, then build again.",
				"If a clean tree reproduces it, the recipe creates them; report it to the AUR maintainer.",
			},
		})
	}
	if parse {
		classes = append(classes, recoveryClass{
			title: "Required recipe material could not be read.",
			steps: []string{
				"A .SRCINFO, a declared source, a mandatory control file, or a shell fragment did not parse as its own format.",
				"Regenerate metadata in the checkout with makepkg --printsrcinfo > .SRCINFO, then build again from a clean tree.",
				"If the tree is clean and current, this is either a recipe defect worth reporting upstream or an input shape this Prolewatch release does not support yet. prolewatch doctor reports the versions this build supports.",
			},
		})
	}
	if race {
		classes = append(classes, recoveryClass{
			title: "The material changed while it was being inspected.",
			steps: []string{
				"Content moved between being read and being hashed, so nothing inspected can be bound to what would be built.",
				"Build again from a clean checkout with no other process writing to the build directory.",
				"If it repeats on an otherwise idle system, the recipe rewrites its own tree during the scan; report it to the AUR maintainer.",
			},
		})
	}
	if reportHasPromptInjection(report) {
		classes = append(classes, recoveryClass{
			title: "Package content tried to steer the AI reviewer.",
			steps: []string{
				"A verdict reported prompt injection, so the contextual half of this review cannot be trusted or approved past.",
				"Read the deterministic findings above. Package text cannot influence those.",
				"Report the injection attempt to the AUR maintainer. An attempt to manipulate the reviewer is itself information about the package.",
			},
		})
	}
	if !report.Coverage.Complete {
		steps := []string{"Mandatory coverage did not complete, so this report describes less than the whole package."}
		for _, note := range report.Coverage.Notes {
			steps = append(steps, "Coverage note: "+terminalInline(note, 1000))
		}
		steps = append(steps,
			"If the package legitimately exceeds a scan ceiling, raise the matching limits value in "+systemConfigDefaultPath+" and build again.",
			"If it does not, the tree is larger or deeper than the recipe implies, which is worth reporting to the AUR maintainer.")
		classes = append(classes, recoveryClass{
			title: "Inspection could not see all of the package.",
			steps: steps,
		})
	}

	// A structural failure with no recognised class must still not be a dead
	// end. This is the floor: it is the reason the function cannot return empty
	// for a blocked, non-approvable report.
	if len(classes) == 0 {
		classes = append(classes, recoveryClass{
			title: "This failure cannot be crossed by an approval.",
			steps: []string{
				"Read the findings above, then build again from a clean AUR checkout.",
				"If a clean build reproduces the failure, report it to the AUR maintainer with the report ID shown below.",
				"prolewatch doctor checks whether this installation and the supported yay and makepkg versions are intact.",
			},
		})
	}
	return classes
}
