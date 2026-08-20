package appx

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Agent-Field/agentfield/sdk/go/ai"
	"github.com/Agent-Field/agentfield/sdk/go/harness"
)

// Fake is a scripted, recording App for tests. Every seam is a plain function
// field; unset seams fail loudly (Harness/AI/Call return an error, Note is
// recorded). Fake also tracks the maximum number of concurrently in-flight
// Harness and Call invocations so phase tests can assert the semaphore bounds
// the Python code enforces (asyncio.Semaphore(n)).
//
// Fake is safe for concurrent use; all recorded slices are guarded by mu.
type Fake struct {
	mu sync.Mutex

	// HarnessFn answers Harness. To mimic a successful structured run, marshal
	// the canned value into dest and return &harness.Result{Parsed: dest}.
	// Use HarnessJSON for the common case.
	HarnessFn func(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error)
	// AIFn answers AI. Use AIJSON for the common "return this JSON" case.
	AIFn func(ctx context.Context, prompt string, opts ...ai.Option) (*ai.Response, error)
	// CallFn answers Call.
	CallFn func(ctx context.Context, target string, input map[string]any) (map[string]any, error)

	// Recorded invocations, in call order.
	Harnesses []HarnessCall
	AIs       []AICall
	Notes     []NoteCall
	Calls     []CallCall

	inflightHarness, maxHarness int
	inflightCall, maxCall       int
}

// HarnessCall is one recorded Harness invocation.
type HarnessCall struct {
	Prompt string
	Schema map[string]any
	Opts   harness.Options
}

// AICall is one recorded AI invocation (the option list is opaque; tests that
// need the system prompt/schema should apply the options to an ai.Request).
type AICall struct {
	Prompt string
	Opts   []ai.Option
}

// NoteCall is one recorded Note invocation.
type NoteCall struct {
	Message string
	Tags    []string
}

// CallCall is one recorded Call invocation.
type CallCall struct {
	Target string
	Input  map[string]any
}

var _ App = (*Fake)(nil)

// Harness implements Harnesser.
func (f *Fake) Harness(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
	f.mu.Lock()
	f.Harnesses = append(f.Harnesses, HarnessCall{Prompt: prompt, Schema: schema, Opts: opts})
	f.inflightHarness++
	if f.inflightHarness > f.maxHarness {
		f.maxHarness = f.inflightHarness
	}
	fn := f.HarnessFn
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflightHarness--
		f.mu.Unlock()
	}()
	if fn == nil {
		return nil, fmt.Errorf("appx.Fake: Harness not scripted (prompt %q)", truncate(prompt, 80))
	}
	return fn(ctx, prompt, schema, dest, opts)
}

// AI implements AIer.
func (f *Fake) AI(ctx context.Context, prompt string, opts ...ai.Option) (*ai.Response, error) {
	f.mu.Lock()
	f.AIs = append(f.AIs, AICall{Prompt: prompt, Opts: opts})
	fn := f.AIFn
	f.mu.Unlock()
	if fn == nil {
		return nil, fmt.Errorf("appx.Fake: AI not scripted (prompt %q)", truncate(prompt, 80))
	}
	return fn(ctx, prompt, opts...)
}

// Note implements Noter.
func (f *Fake) Note(ctx context.Context, message string, tags ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Notes = append(f.Notes, NoteCall{Message: message, Tags: append([]string(nil), tags...)})
}

// Call implements Caller.
func (f *Fake) Call(ctx context.Context, target string, input map[string]any) (map[string]any, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, CallCall{Target: target, Input: input})
	f.inflightCall++
	if f.inflightCall > f.maxCall {
		f.maxCall = f.inflightCall
	}
	fn := f.CallFn
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflightCall--
		f.mu.Unlock()
	}()
	if fn == nil {
		return nil, fmt.Errorf("appx.Fake: Call not scripted (target %q)", target)
	}
	return fn(ctx, target, input)
}

// MaxConcurrentHarness returns the peak number of simultaneously in-flight
// Harness invocations observed so far.
func (f *Fake) MaxConcurrentHarness() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxHarness
}

// MaxConcurrentCalls returns the peak number of simultaneously in-flight Call
// invocations observed so far.
func (f *Fake) MaxConcurrentCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxCall
}

// CallTargets returns the recorded Call targets in order.
func (f *Fake) CallTargets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		out = append(out, c.Target)
	}
	return out
}

// NoteMessages returns the recorded Note messages in order.
func (f *Fake) NoteMessages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.Notes))
	for _, n := range f.Notes {
		out = append(out, n.Message)
	}
	return out
}

// HarnessJSON builds a HarnessFn that answers every invocation by unmarshaling
// the JSON produced by pick(prompt) into dest and returning a successful
// Result whose Parsed is dest — exactly what the SDK runner does on a
// schema-valid run. pick returning an error yields a Result with IsError set
// and that message (the SDK's failure shape), NOT a transport error.
func HarnessJSON(pick func(prompt string, opts harness.Options) (json.RawMessage, error)) func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
	return func(_ context.Context, prompt string, _ map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
		raw, err := pick(prompt, opts)
		if err != nil {
			return &harness.Result{IsError: true, ErrorMessage: err.Error()}, nil
		}
		if dest == nil {
			return &harness.Result{Result: string(raw)}, nil
		}
		if err := json.Unmarshal(raw, dest); err != nil {
			return &harness.Result{IsError: true, ErrorMessage: "fake: unmarshal into dest: " + err.Error()}, nil
		}
		return &harness.Result{Parsed: dest, Result: string(raw)}, nil
	}
}

// AIJSON builds an AIFn that answers every invocation with a response whose
// text content is the JSON produced by pick(prompt).
func AIJSON(pick func(prompt string) (json.RawMessage, error)) func(context.Context, string, ...ai.Option) (*ai.Response, error) {
	return func(_ context.Context, prompt string, _ ...ai.Option) (*ai.Response, error) {
		raw, err := pick(prompt)
		if err != nil {
			return nil, err
		}
		return &ai.Response{Choices: []ai.Choice{{Message: ai.Message{Role: "assistant", Content: []ai.ContentPart{{Type: "text", Text: string(raw)}}}}}}, nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
