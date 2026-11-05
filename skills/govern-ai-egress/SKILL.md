---
name: govern-ai-egress
description: Put Strix Governed AI Egress in front of calls to an external AI provider, self-hosted. Runs the governed egress proxy (npx or container) inside your own boundary, points an OpenAI or Anthropic SDK at it, installs the local Claude Code prompt hook, and verifies the path with a synthetic request. States plainly what the detector does not prove. Use when the user asks to "govern AI egress", "stop PHI going to Claude/OpenAI", "put a proxy in front of the model", "de-identify prompts before they leave", "install the egress prompt hook", or runs /govern-ai-egress.
---

# /govern-ai-egress — self-hosted governed AI egress

This skill wires **Strix Governed AI Egress** into a project the user runs
themselves. Everything runs inside the user's boundary: the proxy, the
detector, and the prompt hook. Nothing is sent to Strix.

> **Claim discipline — say this, and do not say more.** The proxy detects
> labelled and pattern-shaped identifiers, tokenizes them before release,
> re-scans the sanitized text, and releases only the exact bytes it
> authorized. A clean result means **no findings by this detector**
> (`NO_FINDINGS_BY_DETECTOR`), never "contains no PHI". A name with no label
> and no marker word (for example a bare surname in prose) can pass. Do not
> tell the user their data is "fully protected", "HIPAA compliant", or that
> "no PHI can leave". Those claims are false.

## What it is — and is not

| It is | It is not |
|---|---|
| A drop-in proxy for `/v1/chat/completions` (OpenAI shape) and `/v1/messages` (Anthropic shape) | A general network firewall — traffic that does not go through it is not governed |
| A local prompt hook that blocks Claude Code prompts carrying detected identifiers | A guarantee that every identifier is found |
| Self-hosted, with your provider key held by the proxy | A hosted Strix service |
| Elastic-2.0: free to run for your own use | Licensed for you to host for other organisations (see `COMMERCIAL.md`) |

## Step 0 — Ask before doing anything that writes or runs

Show the user this plan and get a yes:

1. Run the proxy (npx or container) — starts a local process.
2. Point one SDK client at it — edits one config value.
3. Install the prompt hook — edits `.claude/settings.json`.
4. Send one synthetic request — calls the provider once, with synthetic data.

Each step is separately approved. Approving one does not approve the next.

## Step 1 — Run the proxy

Requirements: Node 22.13+ (npx path) or Docker (container path); a provider
key for the proxy itself; a policy JSON.

The proxy token is how clients authenticate to the proxy. Generate it into
the environment, never onto a command line (argv is readable by other
processes; the proxy refuses `--token`):

```bash
export STRIX_EGRESS_PROXY_TOKEN="$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')"
```

The provider key (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) belongs to the
proxy and must come from the user's own secret store. **Never ask the user to
paste a key into the chat, and never write one to a file.**

**npx:**

```bash
npx -y -p @strixgov/governed-egress strix-egress-proxy \
  --policy ./policy.json --provider anthropic --evidence-file ./egress-evidence.jsonl
```

**Container** (runs read-only, non-root, loopback only unless TLS is given):

```bash
docker run -d --name strix-egress-proxy \
  --network container:<caller-container> \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e STRIX_EGRESS_PROXY_TOKEN -e ANTHROPIC_API_KEY \
  -v "$PWD/policy.json:/config/policy.json:ro" \
  -v strix-egress-evidence:/data \
  ghcr.io/strixgov/governed-egress-proxy:<version> \
  --provider anthropic --evidence-file /data/evidence.jsonl
```

The proxy listens on `127.0.0.1:8787`. It refuses to start without a
32+ character token, without the provider key, with a non-https
`--base-url`, or on a non-loopback bind without TLS. If it refuses, report
the message verbatim; do not work around it.

Check it is up: `curl -s http://127.0.0.1:8787/healthz`.

## Step 2 — Point the SDK at the proxy

The client uses the proxy's URL and the **proxy token** as its API key. The
real provider key never reaches the client.

**Anthropic (TypeScript / Python):**

```ts
const client = new Anthropic({ baseURL: "http://127.0.0.1:8787", apiKey: process.env.STRIX_EGRESS_PROXY_TOKEN });
```

```python
client = anthropic.Anthropic(base_url="http://127.0.0.1:8787", api_key=os.environ["STRIX_EGRESS_PROXY_TOKEN"])
```

**OpenAI (TypeScript / Python):**

```ts
const client = new OpenAI({ baseURL: "http://127.0.0.1:8787/v1", apiKey: process.env.STRIX_EGRESS_PROXY_TOKEN });
```

```python
client = openai.OpenAI(base_url="http://127.0.0.1:8787/v1", api_key=os.environ["STRIX_EGRESS_PROXY_TOKEN"])
```

Only calls made through this client are governed. Say so if the project has
other call sites that go straight to the provider — list them rather than
implying the whole project is covered.

## Step 3 — Install the Claude Code prompt hook

The hook runs the same detector over each prompt **locally**, before Claude
Code sends it. By default it blocks a prompt with detected identifiers and
reports only categories and counts — never the values.

```bash
npm install -g @strixgov/governed-egress
strix-egress-prompt-hook init            # writes .claude/settings.json in this project
# or: strix-egress-prompt-hook init --user   (writes ~/.claude/settings.json)
```

`init` merges one `UserPromptSubmit` entry and is safe to re-run. To report
without blocking, set `STRIX_EGRESS_HOOK_MODE=warn` in the environment
Claude Code runs in. Any other value blocks. Claude Code picks up hook
changes after a restart.

## Step 4 — Verify with a synthetic request

Use obviously synthetic data only. Never a real record.

```bash
curl -s http://127.0.0.1:8787/v1/messages \
  -H "x-api-key: $STRIX_EGRESS_PROXY_TOKEN" -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"Summarize: Patient: Jane Testcase, MRN: 00012345, DOB: 01/02/1970."}]}'
```

Use a model the proxy allows (`--model` / `--allow-model`); a refused model
is the proxy working, not a failure of the check.

Then read the last evidence line (`tail -1 egress-evidence.jsonl`). Report
what it shows: a decision, categories and counts, hashes. It should never
contain the name or MRN. If a value appears in the evidence file, stop and
report it as a defect.

For the hook, submit a synthetic prompt such as
`Patient: Jane Testcase, MRN 00012345` in Claude Code and confirm it is
blocked with a category count and no value.

## What to report back

- Which steps ran and which the user declined.
- The proxy URL, and which call sites now go through it (and which do not).
- The synthetic verification result, quoted from the evidence line.
- The ceiling, in these words: *a clean result means no findings by this
  detector, not that the data contains no sensitive information.*
