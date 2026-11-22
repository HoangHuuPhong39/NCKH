# AI Security Scanner — Application Package

This directory is the **Single Source of Truth (SSOT)** for the `AI_Security_Scanner` application: the 5-layer AST taint-tracking SAST engine, OSS supply-chain/SCA scanner, dynamic OWASP LLM red-teaming modules, Flask Web Dashboard & OpenAPI 3.0.3 API, hardened AI Guard Proxy v3.1, datasets, and test suite.

For the full architecture overview, project structure, and v2 roadmap, see the repository root [README.md](../README.md).

## Quick Commands

```bash
# 1. Install core dependencies (inside a virtualenv)
pip install -r requirements.txt

# 2. (Optional) Configure local environment variables
cp .env.example .env

# 3. Run offline static AST taint-tracking SAST scan on the sample vulnerable app
python main.py --sast data/samples/vulnerable_oss_ai_app --no-external-tools

# 4. Run OSS AI supply-chain & checkpoint audit
python main.py --oss data/samples/vulnerable_oss_ai_app

# 5. Launch interactive red-teaming CLI or list all modules
python main.py --list-modules
python main.py

# 6. Start Web Dashboard (http://127.0.0.1:5000 | Swagger UI: /api/docs)
python web/app.py

# 7. Start Hardened AI Guard Proxy v3.1 (http://127.0.0.1:8000)
python -m guard_proxy.app

# 8. Run automated test suite with coverage (requires requirements-dev.txt)
pytest --cov=core --cov=modules --cov=web --cov=guard_proxy
```
