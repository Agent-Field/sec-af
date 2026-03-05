"""Minimal isolated harness test — run inside Docker container.

Tests schema output with varying prompt sizes to isolate the failure.
Usage: docker exec sec-af-agent python3 /app/test_harness.py
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import time

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

from agentfield.harness._runner import HarnessRunner
from pydantic import BaseModel, Field

REPO_PATH = "/workspaces/Damn-Vulnerable-GraphQL-Application"


class EnrichedFinding(BaseModel):
    title: str = Field(description="Human-readable title for the finding")
    description: str = Field(description="Detailed description of the vulnerability")
    cwe_id: str = Field(description="CWE identifier (e.g. 'CWE-89')")
    severity: str = Field(description='One of: "critical", "high", "medium", "low", "info"')
    confidence: str = Field(description='One of: "high", "medium", "low"')
    data_flow_summary: str = Field(description="Natural language summary of the data flow")


class SimpleOutput(BaseModel):
    answer: str = Field(description="Your answer as a string")


SHORT_PROMPT = (
    "You are a security analyst. Analyze this Python code for SQL injection:\n\n"
    "```python\n"
    "def get_user(user_id):\n"
    "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
    "    return db.execute(query)\n"
    "```\n\n"
    "Produce a vulnerability finding."
)

LARGE_CONTEXT = "RECON CONTEXT:\n" + json.dumps(
    {
        "architecture": {
            "app_type": "web_api",
            "modules": [f"module_{i} | src/mod{i}/ | python | Module {i} description" for i in range(30)],
            "entry_points": [f"http | GET /api/endpoint{i} | src/routes.py:{i * 10} | false" for i in range(40)],
            "trust_boundaries": [f"boundary_{i} | zone_a | zone_b | Description {i}" for i in range(10)],
            "services": [f"service_{i} | database | localhost:{5432 + i} | password" for i in range(5)],
            "api_endpoints": [
                f"GET | /api/v1/resource{i} | handler_{i} | src/api.py:{i * 5} | true | false" for i in range(50)
            ],
        },
        "data_flows": {
            "flows": ["request.body | sql.execute | false | src/db.py, src/routes.py" for _ in range(20)],
            "sanitization_points": [],
            "sinks": [f"sql_execute | src/db.py:{i * 10} | run_query | Direct concatenation" for i in range(15)],
        },
        "dependencies": {
            "sbom": [f"package_{i} | 1.{i}.0 | pip | true | MIT" for i in range(40)],
            "known_cves": [
                f"CVE-2023-{1000 + i} | package_{i} | 1.{i}.0 | 1.{i + 1}.0 | 7.5 | true | unknown" for i in range(5)
            ],
        },
    },
    indent=2,
)

LONG_PROMPT = (
    "ROLE:\nYou are Step 2 FindingEnricher for SEC-AF HUNT phase.\n\n"
    "TASK:\nEnrich one scanned vulnerability location into one complete finding.\n\n"
    f"{LARGE_CONTEXT}\n\n"
    "LOCATION:\n"
    "- File path: core/views.py\n"
    "- Start line: 85\n"
    "- Pattern type: sql_injection\n"
    "- Code snippet:\n"
    "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
    "    result = db.execute(query)\n\n"
    "WORKFLOW:\n"
    "1. Read the file at the file path above.\n"
    "2. Analyze the code for the vulnerability.\n"
    "3. Write the final JSON output file.\n"
)


async def run_test(name, prompt, schema, project_dir=REPO_PATH):
    print(f"\n{'=' * 60}")
    print(f"TEST: {name}")
    print(f"  prompt: {len(prompt)} chars (~{len(prompt) // 4} tokens)")
    schema_json = json.dumps(schema.model_json_schema())
    print(f"  schema: {len(schema_json)} chars")

    runner = HarnessRunner()
    start = time.monotonic()
    try:
        result = await runner.run(
            prompt=prompt,
            schema=schema,
            provider="opencode",
            model="openrouter/moonshotai/kimi-k2.5",
            project_dir=project_dir,
            cwd=tempfile.mkdtemp(prefix="test-harness-"),
            schema_max_retries=0,
        )
        elapsed = time.monotonic() - start
        print(f"  elapsed: {elapsed:.1f}s")
        print(f"  is_error: {result.is_error}")
        print(f"  error_message: {result.error_message}")
        print(f"  num_turns: {result.num_turns}")
        if result.parsed:
            print(f"  PARSED OK: {json.dumps(result.parsed.model_dump(), indent=2)[:500]}")
        if result.result:
            print(f"  stdout[0:300]: {result.result[:300]}")
        return not result.is_error
    except Exception as e:
        elapsed = time.monotonic() - start
        print(f"  EXCEPTION after {elapsed:.1f}s: {e}")
        return False


async def main():
    if not os.path.isdir(REPO_PATH):
        print(f"ERROR: {REPO_PATH} not found. Run a scan first to clone it.")
        sys.exit(1)

    test_arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    results = {}

    if test_arg in ("1", "all"):
        results["simple_short"] = await run_test("SimpleOutput + short prompt", "What is 2+2?", SimpleOutput)

    if test_arg in ("2", "all"):
        results["enriched_short"] = await run_test("EnrichedFinding + SHORT prompt", SHORT_PROMPT, EnrichedFinding)

    if test_arg in ("3", "all"):
        results["enriched_long"] = await run_test("EnrichedFinding + LONG prompt (~20KB)", LONG_PROMPT, EnrichedFinding)

    if test_arg in ("4", "all"):
        # Test 4: CONCURRENT enrichment calls (simulates real hunt phase)
        print(f"\n{'=' * 60}")
        print("TEST: CONCURRENT x4 EnrichedFinding + LONG prompt")
        concurrent_start = time.monotonic()
        variants = [
            ("sql_injection", "core/views.py", "85"),
            ("auth_bypass", "core/auth.py", "42"),
            ("data_exposure", "core/models.py", "110"),
            ("dos_regex", "core/helpers.py", "23"),
        ]
        tasks = []
        for pattern, fpath, line in variants:
            variant_prompt = (
                LONG_PROMPT.replace("sql_injection", pattern).replace("core/views.py", fpath).replace("85", line)
            )
            tasks.append(run_test(f"CONCURRENT-{pattern}", variant_prompt, EnrichedFinding))
        concurrent_results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - concurrent_start
        print(f"\n  CONCURRENT total elapsed: {elapsed:.1f}s")
        for i, (pattern, _, _) in enumerate(variants):
            r = concurrent_results[i]
            if isinstance(r, Exception):
                results[f"concurrent_{pattern}"] = False
                print(f"  FAIL (exception): concurrent_{pattern}: {r}")
            else:
                results[f"concurrent_{pattern}"] = r
                print(f"  {'PASS' if r else 'FAIL'}: concurrent_{pattern}")

    print(f"\n{'=' * 60}")
    print("SUMMARY:")
    for name, passed in results.items():
        print(f"  {'PASS' if passed else 'FAIL'}: {name}")


if __name__ == "__main__":
    asyncio.run(main())
