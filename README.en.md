<p align="center">
  <img src="docs/assets/logo.svg" width="112" alt="Aegis">
</p>

<h1 align="center">Aegis</h1>

<p align="center">
  <b>A security control plane for LLMs and AI agents.</b><br>
  Your code and data reach the model as pseudonyms. Real values come back only where policy allows.
</p>

<p align="center">
  <a href="https://github.com/Paffin/Aegis/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Paffin/Aegis/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.80%2B-93450a">
  <img alt="unsafe" src="https://img.shields.io/badge/unsafe-forbidden-brightgreen">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

<p align="center"><a href="README.md">Русский</a> · most documentation is in Russian</p>

<p align="center">
  <img src="docs/assets/flow.svg" width="900" alt="Client, Aegis gateway, model: values are replaced by pseudonyms, the answer comes back with real values by destination">
</p>

## What it is

Aegis is a gateway that sits between developer tools or agents and LLM providers. The only change a client needs is the API base URL.

1. **Detects** secrets, infrastructure names, personal data, employee names and company terms.
2. **Replaces** them with pseudonyms that keep the shape of the value (a host stays a host, an IP stays an IP, subnets stay intact). There is no mapping store: a pseudonym is an HMAC of the value under the tenant key, so the gateway is stateless and scales horizontally.
3. **Restores** real values in the answer depending on the destination: into text and files, yes; into a network command, no. A tool call that would carry a secret out is replaced by an explanation the agent can read.
4. **Audits** without values, and applies a three-condition rule: private data plus untrusted content (a web page, `node_modules`) forbids network calls.

## Try it in two minutes

You need `cargo` and `python3`, no provider keys.

```bash
git clone https://github.com/Paffin/Aegis && cd Aegis
scripts/demo.sh                      # client -> Aegis -> a "provider" that prints what it received
cargo run -q -p aegis-cli -- scan path/to/repo --zone corp.local   # what would be masked in your files (no values printed)
```

## Supported

| Protocol | Endpoints | Clients |
|---|---|---|
| Anthropic Messages | `/v1/messages`, `count_tokens` | Claude Code, Cline, Roo, Kilo, Continue, Aider, Zed, OpenCode |
| OpenAI Responses (stateless) | `/v1/responses` | Codex CLI, OpenAI Agents SDK |
| OpenAI Chat Completions | `/v1/chat/completions` | Cline, Continue, Aider, Qwen Code, Kimi CLI, Goose, Open WebUI, any SDK |
| OpenAI Completions / Embeddings | `/v1/completions`, `/v1/embeddings` | autocomplete (FIM), code indexing |
| Google Gemini | `generateContent`, `streamGenerateContent`, `countTokens`, `embedContent` | Gemini CLI, Google GenAI SDKs |

Providers: Anthropic, OpenAI, Azure OpenAI, Google Gemini, DeepSeek, Qwen, Kimi, GLM, MiniMax, Doubao, Hunyuan, Qianfan, SiliconFlow, OpenRouter and others, plus local vLLM, SGLang, Ollama and llama.cpp without a key. See [docs/PROVIDERS.md](docs/PROVIDERS.md) and [docs/CLIENTS.md](docs/CLIENTS.md) (Russian).

Cursor, Windsurf and the built-in GitHub Copilot completions talk to the vendors' own servers and cannot be pointed at a gateway; only perimeter blocking applies ([`deploy/egress`](deploy/egress)).

## Status: alpha, read this

Measured with `aegis-bench`, repeated in CI: 4.5 false positives per 10k lines on 2.3M lines of open-source code (target: below 1; mostly real values such as package author e-mails); 100 % recall on 21 of 22 synthetic types and 98.9 % on assignment passwords (the corpus was written by the detectors' author, so the figure is optimistic); warm-turn latency p50 ≈ 4 ms / p95 ≈ 6 ms at ~219k tokens of context; under load (30 req/s, ~860 KB history, 244 concurrent streams, one 4-core machine, generator and mock in the same process) the gateway adds p95 ≈ 26 ms to the time to first byte with no errors; 216 tests (including property tests, fuzzing and 1300+ exfiltration scenarios).

**Verified with real clients:** Claude Code, Codex CLI, Qwen Code, Gemini CLI, OpenCode, Aider, Continue and Cline run against Aegis and a mock provider (`scripts/clients.sh`): values are masked in every request and in the history, a harmless command runs with the real value, a call that would carry a secret out is replaced by an explanation. **Not verified yet, and the main risk:** no real provider was called (whether providers accept thinking signatures and `thoughtSignature` after passing through Aegis is unconfirmed); other clients (Roo and Kilo Code, Zed, Goose, Open WebUI, …) are tested only with synthetic requests. The Docker image was built and started, the Helm chart renders, but nothing was applied to a cluster. Details: [docs/STATUS.md](docs/STATUS.md).

Aegis does not anonymize (pseudonymization is reversible, so data stays personal data under GDPR), does not stop a malicious insider, does not detect prompt injection (it limits the consequences), and does not see tool execution on the developer's machine. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Layout

```
crates/
  aegis-core      detection, pseudonyms, policy, restoration, shell lexer, bundles
  aegis-gateway   protocols (Anthropic, OpenAI, Gemini), streaming, HTTP server, audit, metrics
  aegis-cli       `aegis`: keys, bundles, policy tests, virtual keys, reports, scan
  aegis-bench     measurements: false positives, recall, latency
```

## License

[Apache-2.0](LICENSE). Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
