// ==============================================================================
// web/static/js/auth_and_security.js
// - Transparent Bearer JWT injection for all /api/* fetch() calls
// - Login Modal when SCANNER_REQUIRE_AUTH=true (401 handling)
// - Safe delegated event listeners replacing unsafe inline onclick XSS sinks
// ==============================================================================
(function () {
  "use strict";

  const TOKEN_KEY = "ai_scanner_jwt_token";

  function getStoredToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function setStoredToken(token) {
    try {
      if (token) sessionStorage.setItem(TOKEN_KEY, token);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch (e) {}
  }

  window.getScannerAuthToken = getStoredToken;
  window.setScannerAuthToken = setStoredToken;

  window.getAuthSseUrl = function (scanToken) {
    const params = new URLSearchParams();
    if (scanToken) params.set("scan_token", scanToken);
    const jwt = getStoredToken();
    if (jwt) params.set("token", jwt);
    const qs = params.toString();
    return qs ? `/api/scan/stream?${qs}` : "/api/scan/stream";
  };

  window.encodeDataB64 = function (text) {
    try {
      const bytes = new TextEncoder().encode(String(text || ""));
      let bin = "";
      bytes.forEach((b) => { bin += String.fromCharCode(b); });
      return btoa(bin);
    } catch (e) {
      return "";
    }
  };

  window.decodeDataB64 = function (b64) {
    try {
      const bin = atob(String(b64 || ""));
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    } catch (e) {
      return "";
    }
  };

  function showAuthModal(msg) {
    const modal = document.getElementById("scanner-auth-modal");
    if (!modal) return;
    const errEl = document.getElementById("auth-modal-error");
    if (errEl) {
      errEl.textContent = msg || "";
      errEl.style.display = msg ? "block" : "none";
    }
    modal.style.display = "flex";
    const inp = document.getElementById("auth-api-key-input");
    if (inp) setTimeout(() => inp.focus(), 50);
  }

  function hideAuthModal() {
    const modal = document.getElementById("scanner-auth-modal");
    if (modal) modal.style.display = "none";
  }

  window.showScannerAuthModal = showAuthModal;

  window.scannerLogout = function () {
    setStoredToken("");
    showAuthModal("Đã đăng xuất. Vui lòng nhập API Key quản trị để tiếp tục.");
  };

  // Wrap native window.fetch so every /api/* request automatically sends Bearer token
  const _origFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const urlStr = typeof input === "string" ? input : (input && input.url ? input.url : "");
    const isSameOriginApi = urlStr.startsWith("/api/") || urlStr.startsWith(window.location.origin + "/api/");
    const opts = init ? Object.assign({}, init) : {};

    if (isSameOriginApi) {
      const token = getStoredToken();
      if (token) {
        const headers = new Headers(opts.headers || (input instanceof Request ? input.headers : undefined));
        if (!headers.has("Authorization") && !headers.has("X-API-Key")) {
          headers.set("Authorization", "Bearer " + token);
        }
        opts.headers = headers;
      }
    }

    const resp = await _origFetch(input, opts);
    if (isSameOriginApi && resp.status === 401 && !urlStr.includes("/api/auth/login")) {
      setStoredToken("");
      showAuthModal("Phiên đăng nhập yêu cầu xác thực (401 Unauthorized). Vui lòng nhập Admin API Key.");
    }
    return resp;
  };

  async function submitAuthForm(ev) {
    if (ev) ev.preventDefault();
    const keyInput = document.getElementById("auth-api-key-input");
    const errEl = document.getElementById("auth-modal-error");
    const btn = document.getElementById("auth-submit-btn");
    const apiKey = (keyInput ? keyInput.value : "").trim();
    if (!apiKey) {
      if (errEl) {
        errEl.textContent = "Vui lòng nhập SCANNER_ADMIN_API_KEY.";
        errEl.style.display = "block";
      }
      return;
    }
    if (btn) btn.disabled = true;
    try {
      const r = await _origFetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: apiKey }),
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok && data.token) {
        setStoredToken(data.token);
        if (keyInput) keyInput.value = "";
        hideAuthModal();
        // Reload authenticated views cleanly
        if (typeof loadConfigData === "function") loadConfigData();
        if (typeof loadModulesData === "function") loadModulesData();
        if (typeof refreshAllTelemetryAndMetrics === "function") refreshAllTelemetryAndMetrics();
      } else if (errEl) {
        errEl.textContent = data.message || data.error || "API Key không hợp lệ.";
        errEl.style.display = "block";
      }
    } catch (e) {
      if (errEl) {
        errEl.textContent = "Lỗi kết nối máy chủ: " + e.message;
        errEl.style.display = "block";
      }
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // Safe delegated click handlers (eliminates inline onclick XSS vectors)
  document.addEventListener("click", function (e) {
    const copyBtn = e.target.closest("[data-copy-b64]");
    if (copyBtn) {
      const text = window.decodeDataB64(copyBtn.getAttribute("data-copy-b64"));
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          const orig = copyBtn.textContent;
          copyBtn.textContent = "Copied!";
          setTimeout(() => { copyBtn.textContent = orig; }, 1400);
        }).catch(() => {});
      }
      return;
    }

    const recBtn = e.target.closest("[data-rec-mods-b64]");
    if (recBtn && typeof window.applyRecommendedModules === "function") {
      try {
        const mods = JSON.parse(window.decodeDataB64(recBtn.getAttribute("data-rec-mods-b64")));
        if (Array.isArray(mods)) window.applyRecommendedModules(mods);
      } catch (err) {}
    }
  });

  document.addEventListener("DOMContentLoaded", async function () {
    const form = document.getElementById("scanner-auth-form");
    if (form) form.addEventListener("submit", submitAuthForm);

    try {
      const st = await _origFetch("/api/auth/status", {
        headers: getStoredToken() ? { Authorization: "Bearer " + getStoredToken() } : {},
      }).then((r) => r.json());
      if (st && st.require_auth && !st.authenticated) {
        showAuthModal("");
      }
    } catch (e) {}
  });
})();
