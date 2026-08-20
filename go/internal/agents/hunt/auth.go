package hunt

// Ports src/sec_af/agents/hunt/auth.py.

import (
	"context"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/prompts"
	"github.com/Agent-Field/sec-af/go/internal/recontext"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

const authPromptPath = "hunt/auth.txt"

// authTargetCWEs ports auth.py `_TARGET_CWES`. Order is load-bearing: the list
// is joined with ", " into the prompt's {{TARGET_CWES}} slot.
var authTargetCWEs = []string{"CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-352"}

// authDepthLabel ports auth.py _depth_label:
//
//	normalized = depth.lower().strip()
//	return normalized if normalized in {"quick", "standard", "thorough"} else "standard"
//
// Python parity: lower() runs BEFORE strip(), which is immaterial (neither
// changes the other's result), but the STRIP is what distinguishes this from
// config.NormalizeDepth — " THOROUGH " normalizes to "thorough" here and to
// "standard" there. auth.py is the only module that trims.
func authDepthLabel(depth string) string {
	normalized := strings.TrimSpace(strings.ToLower(depth))
	switch normalized {
	case "quick", "standard", "thorough":
		return normalized
	default:
		return "standard"
	}
}

// authBuildPrompt ports auth.py _build_prompt — the six template substitutions.
// It returns the recon context alongside the prompt because run_auth_hunter
// recomputes the same string for the enrichment step.
func authBuildPrompt(template, repoPath string, recon schemas.ReconResult, depth string) (string, string) {
	reconContext := recontext.ReconContextForAuth(recon)
	out := strings.ReplaceAll(template, "{{REPO_PATH}}", repoPath)
	out = strings.ReplaceAll(out, "{{DEPTH}}", authDepthLabel(depth))
	out = strings.ReplaceAll(out, "{{TARGET_CWES}}", strings.Join(authTargetCWEs, ", "))
	out = strings.ReplaceAll(out, "{{RECON_CONTEXT}}", reconContext)
	out = strings.ReplaceAll(out, "{{LANGUAGE_HINTS}}", recontext.LanguageHintsForContext(recon))
	out = strings.ReplaceAll(out, "{{FRAMEWORK_HINTS}}", recontext.FrameworkHintsForContext(recon))
	return out, reconContext
}

// authScanPrompt builds the exact prompt run_auth_hunter sends.
//
// Python parity: auth is the ONLY hunter whose appended block is headed
// "EXECUTION CONSTRAINTS:" rather than "CONTEXT:", it is the only one that ends
// with a trailing newline, and it carries no repository-path or depth line —
// both already reached the prompt through the template's {{REPO_PATH}} and
// {{DEPTH}} markers. run_auth_hunter also passes the ALREADY-normalized label
// into _build_prompt, which normalizes again; authDepthLabel is idempotent, so
// the port folds the double normalization into one call.
func authScanPrompt(repoPath string, recon schemas.ReconResult, depth, earlyStop string) (scanPrompt, reconContext string) {
	built, reconContext := authBuildPrompt(prompts.MustLoad(authPromptPath), repoPath, recon, authDepthLabel(depth))
	scanPrompt = built +
		"\n\nEXECUTION CONSTRAINTS:\n" +
		"- Early stop rule: if you inspect " +
		earlyStop + " files without credible auth issues, " +
		"stop and return empty findings.\n"
	return scanPrompt, reconContext
}

func runAuthHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth, earlyStop string,
) (schemas.HuntResult, error) {
	scanPrompt, reconContext := authScanPrompt(repoPath, recon, depth, earlyStop)
	return runHunterBody(ctx, app, repoPath, hunterSpec{
		ScanPrompt:         scanPrompt,
		ReconContext:       reconContext,
		FindingType:        "sast",
		Strategy:           "auth",
		EmptyStrategiesRun: nil, // Python: bare HuntResult()
	})
}

// RunAuthHunter ports auth.py run_auth_hunter.
func RunAuthHunter(
	ctx context.Context, app appx.Harnesser, repoPath string,
	recon schemas.ReconResult, depth string, maxFilesWithoutSignal int,
) (schemas.HuntResult, error) {
	return runAuthHunter(ctx, app, repoPath, recon, depth, strconv.Itoa(maxFilesWithoutSignal))
}
