# Curated White-Box SAST & OSS Supply-Chain Test Fixtures

> **Security Notice**: All API keys, tokens, vulnerable scripts, and model configs in this directory are **intentional synthetic test fixtures** used exclusively by `tests/unit/test_code_scanner_advanced.py` and `tests/unit/test_oss_scanner_advanced.py`. **None of the credentials are real or active.**

## Fixture Catalog

| Fixture | Level / Focus | What It Tests |
| --- | --- | --- |
| `amateur_chatbot.py` | **Amateur / Beginner** | Typical naive mistakes: plaintext API key, f-string prompt concat, `verify=False`, missing timeout, `pickle.load`, `eval(llm_output)`, raw SQL f-string, system prompt print. |
| `enterprise_ai_copilot.py` | **Professional Enterprise** | Production-style typed microservice mixing 4 safe decoy methods (must yield **0 FP**) with subtle multi-layer flaws (XOR token, `PromptEnvelope` taint, dynamic `importlib` `pickle.loads`, `**kwargs` `shell=bool(1)` & `trust_remote_code=(not False)`, `getattr` SSRF + missing timeout, `\|` Vector DB filter injection). |
| `advanced_agent_metaprog.py` | **Metaprogramming** | Decorator-hidden Text-to-SQL sink (`@_auto_commit_query`), `compile()` + `types.FunctionType` RCE without `eval`/`exec`, and `**user_filters` Vector DB cross-tenant leak. |
| `cross_file_test/` | **Cross-File Taint (Layer 5)** | Multi-module taint propagation (`routes.py` → `utils.py` → `llm_executor.py`) for prompt injection and downstream SQLi. |
| `false_positive_trap.py` | **Zero-FP Control** | Strict negative control (`yaml.safe_load`, `ast.literal_eval`, `subprocess.run(..., shell=False)`, role-separated LLM calls, dangerous words in comments) — must emit **0 findings**. |
| `ai_gateway.ts` | **TypeScript / JS** | `Array.join('-')` split Anthropic key, Tagged Template prompt injection, and `new Function(...)` RCE. |
| `agent_config.yaml` | **YAML Anchor/Alias** | Safe anchor expansion (`&unsafe_defaults` / `*unsafe_defaults`) exposing hidden `verify_ssl: false`, `trust_remote_code: true`, `max_tokens: -1`, `sandbox_mode: off`, and `credential_ref`. |
| `Modelfile` | **Ollama Modelfile** | Unbounded `num_ctx`/`num_predict`, embedded `postgres://` & `whsec_` secrets, and conditional `DEBUG_OVERRIDE_99` backdoor in `SYSTEM`. |
| `config.json` & `requirements.txt` | **OSS Supply Chain / SCA** | HuggingFace `auto_map` code execution risk and vulnerable AI/ML dependency SemVer checks. |
