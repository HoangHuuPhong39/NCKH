# 🌐 Bilingual Localization Guide (Unified i18n.js Architecture)

## Overview
All UI translations (Vietnamese `vi` & English `en`) are unified around [`web/static/i18n.js`](static/i18n.js) as the Single Source of Truth:
- **`web/static/i18n.js`**: Defines the complete `TRANSLATIONS` dictionary (`vi` / `en`), `applyTranslations(lang)`, and `t(key)`.
- **`web/static/js/dashboard.js`**: Delegates `toggleLanguage()` to `applyTranslations(currentAppLang)` and syncs `window.currentAppLang` + `localStorage['ai_scanner_lang']`.
- **`web/static/js/auth_and_security.js`**: External authentication modal & XSS-safe delegated click utilities (no inline `<script>` tags anywhere; protected by `script-src-elem 'self'`).

## Adding New Translatable Strings
1. Add both `vi` and `en` entries to `TRANSLATIONS` in `web/static/i18n.js`.
2. Tag the HTML element in `web/templates/index.html` with `data-i18n="your_key"` (or `data-i18n-placeholder="your_key"` for inputs).
3. For dynamic JS strings inside `web/static/js/dashboard.js`, call `t('your_key')`.

## Translation Rules
- **Translate**: Navigation items, section headings, labels, buttons, empty states, toasts, and guidance copy.
- **Do NOT translate**: Attack module identifiers (`Prompt Injection`, `Jailbreak`, `RAG Security`), OWASP codes (`LLM01`–`LLM10`), MITRE ATLAS IDs (`AML.T0051`), raw payloads, model responses, or technical acronyms (`CVSS`, `SSE`, `API`, `SARIF`, `JSON`).
