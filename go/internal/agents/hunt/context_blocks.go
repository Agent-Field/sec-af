package hunt

// The inline JSON recon-context blocks four hunters build for themselves
// instead of calling into src/sec_af/context.py.

import (
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// headEntryPoints ports Python's `architecture.entry_points[:n]`.
//
// The result is always NON-NIL, because pyfmt.Dumps renders a nil Go slice as
// `null` while a Python list slice of an empty list is `[]`. Every other
// element of the block is a struct, whose rendering needs no such care.
func headEntryPoints(items []schemas.EntryPoint, n int) []schemas.EntryPoint {
	if n > len(items) {
		n = len(items)
	}
	out := make([]schemas.EntryPoint, 0, n)
	return append(out, items[:n]...)
}

// headAPIEndpoints ports `architecture.api_surface[:n]`. See headEntryPoints.
func headAPIEndpoints(items []schemas.APIEndpoint, n int) []schemas.APIEndpoint {
	if n > len(items) {
		n = len(items)
	}
	out := make([]schemas.APIEndpoint, 0, n)
	return append(out, items[:n]...)
}

// headDataFlows ports `data_flows.flows[:n]`. See headEntryPoints.
func headDataFlows(items []schemas.DataFlow, n int) []schemas.DataFlow {
	if n > len(items) {
		n = len(items)
	}
	out := make([]schemas.DataFlow, 0, n)
	return append(out, items[:n]...)
}

// entryFlowContextBlock ports the `_recon_context_block` helper that
// agents/hunt/dos.py, ssrf.py and xss.py each declare — three byte-identical
// copies of:
//
//	entry_points = [entry.model_dump() for entry in recon_result.architecture.entry_points[:10]]
//	data_flows = [flow.model_dump() for flow in recon_result.data_flows.flows[:10]]
//	context = {
//	    "app_type": recon_result.architecture.app_type,
//	    "auth_model": recon_result.security_context.auth_model,
//	    "frameworks": recon_result.frameworks,
//	    "languages": recon_result.languages,
//	    "entry_points": entry_points,
//	    "data_flows": data_flows,
//	}
//	return json.dumps(context, indent=2)
//
// The dict's key order is INSERTION order, which is not alphabetical, so the
// port builds a pyfmt.Ordered rather than a Go map (see DESIGN.md §2b) — and
// pyfmt.Dumps, not encoding/json, because the text reaches the LLM verbatim and
// CPython does not escape `<`, `>` or `&` while Go's encoder does.
//
// `app_type` is `str | None`: a nil *string renders as `null`, exactly as
// model_dump() -> json.dumps does for None.
func entryFlowContextBlock(recon schemas.ReconResult) string {
	return pyfmt.Dumps(pyfmt.O(
		"app_type", recon.Architecture.AppType,
		"auth_model", recon.SecurityContext.AuthModel,
		"frameworks", recon.Frameworks,
		"languages", recon.Languages,
		"entry_points", headEntryPoints(recon.Architecture.EntryPoints, 10),
		"data_flows", headDataFlows(recon.DataFlows.Flows, 10),
	), 2)
}

// businessLogicContextBlock ports agents/hunt/business_logic.py
// `_recon_context_block` — a WIDER projection than entryFlowContextBlock, with
// different limits (15 entry points, 20 endpoints, 20 flows), the api_surface
// added, and a different key order:
//
//	{"app_type", "frameworks", "languages", "auth_model", "auth_details",
//	 "entry_points", "api_surface", "data_flows"}
func businessLogicContextBlock(recon schemas.ReconResult) string {
	return pyfmt.Dumps(pyfmt.O(
		"app_type", recon.Architecture.AppType,
		"frameworks", recon.Frameworks,
		"languages", recon.Languages,
		"auth_model", recon.SecurityContext.AuthModel,
		"auth_details", recon.SecurityContext.AuthDetails,
		"entry_points", headEntryPoints(recon.Architecture.EntryPoints, 15),
		"api_surface", headAPIEndpoints(recon.Architecture.APISurface, 20),
		"data_flows", headDataFlows(recon.DataFlows.Flows, 20),
	), 2)
}
