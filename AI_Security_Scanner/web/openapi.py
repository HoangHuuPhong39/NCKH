# -*- coding: utf-8 -*-
"""
web/openapi.py - Synchronized High-Contrast Cybersecurity OpenAPI 3.0 & Swagger UI
Fully unified with the AI Security Scanner v2.0 Enterprise Design System (Dark/Light Theme,
Brand Logo, Cyber SOC UI, and 100% Professional Cybersecurity English Localization).
"""

SWAGGER_UI_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>REST API Console & Specification · AI Security Scanner v2.0 Enterprise</title>
  <link rel="stylesheet" href="/static/swagger-ui.css" />
  <link rel="icon" type="image/jpeg" href="/static/logo.jpg">

  <script>
    // Immediate Theme Initialization to avoid white flash
    (function() {
      try {
        const saved = localStorage.getItem('ai_scanner_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', saved);
      } catch(e) {}
    })();
  </script>

  <style>
    /* ══════════════════════════════════════════════════════════════════
       DESIGN SYSTEM - EXACT SYNCHRONIZATION WITH MAIN APPLICATION
       ══════════════════════════════════════════════════════════════════ */
    :root {
      /* Dark Theme: Cyber SOC Navy & Sapphire Glow */
      --bg-base: #060b17;
      --bg-surface: #0a1021;
      --bg-surface-hover: #101a35;
      --bg-card: #0c1428;
      --bg-card-secondary: #080e1c;
      --bg-input: #070d1a;
      --border-color: #162444;
      --border-light: #223764;

      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --text-heading: #f8fafc;
      --text-body: #cbd5e1;

      /* Primary Cyber Blue Accent */
      --accent: #0284c7;
      --accent-hover: #0369a1;
      --accent-cyan: #38bdf8;
      --accent-subtle: rgba(2, 132, 199, 0.14);
      --accent-glow: rgba(2, 132, 199, 0.35);

      /* Severity Colors */
      --sev-critical: #ef4444;
      --sev-high: #f97316;
      --sev-medium: #f59e0b;
      --sev-low: #0ea5e9;

      --status-success: #10b981;
      --status-danger: #ef4444;

      --code-bg: #040812;
      --topbar-height: 64px;
      --font-mono: "JetBrains Mono", Consolas, Menlo, monospace;
      --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --radius-sm: 6px;
      --radius-md: 9px;
      --radius-lg: 12px;
    }

    [data-theme="light"] {
      --bg-base: #f1f5f9;
      --bg-surface: #ffffff;
      --bg-surface-hover: #e2e8f0;
      --bg-card: #ffffff;
      --bg-card-secondary: #f8fafc;
      --bg-input: #ffffff;
      --border-color: #cbd5e1;
      --border-light: #94a3b8;

      --text-primary: #0f172a;
      --text-secondary: #475569;
      --text-muted: #64748b;
      --text-heading: #0f172a;
      --text-body: #334155;

      --accent: #0284c7;
      --accent-hover: #0369a1;
      --accent-cyan: #0284c7;
      --accent-subtle: rgba(2, 132, 199, 0.1);
      --accent-glow: rgba(2, 132, 199, 0.2);

      --code-bg: #0f172a;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 0;
      background-color: var(--bg-base);
      color: var(--text-body);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      font-size: 14.5px;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.2s ease, color 0.2s ease;
    }

    /* ══════════════════════════════════════════════════════════════════
       TOPBAR NAVIGATION (SYNCHRONIZED WITH MAIN APP)
       ══════════════════════════════════════════════════════════════════ */
    .docs-nav {
      position: sticky;
      top: 0;
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 28px;
      height: var(--topbar-height);
      background-color: var(--bg-surface);
      border-bottom: 1px solid var(--border-color);
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.25);
      backdrop-filter: blur(12px);
    }

    .nav-brand {
      display: flex;
      align-items: center;
      gap: 14px;
      text-decoration: none;
    }

    /* Synchronized Logo Styling matching Main Dashboard */
    .sidebar-brand-logo-wrap {
      position: relative;
      flex-shrink: 0;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .sidebar-brand-logo {
      width: 38px;
      height: 38px;
      border-radius: 9px;
      object-fit: cover;
      border: 1.5px solid var(--accent);
      background: #040812;
      box-shadow: 0 0 10px var(--accent-glow);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .nav-brand:hover .sidebar-brand-logo {
      transform: scale(1.05);
      box-shadow: 0 0 16px rgba(2, 132, 199, 0.5);
    }
    .logo-status-indicator {
      position: absolute;
      bottom: -2px;
      right: -2px;
      width: 9px;
      height: 9px;
      background-color: var(--status-success);
      border-radius: 50%;
      border: 2px solid var(--bg-surface);
      box-shadow: 0 0 6px var(--status-success);
    }

    .brand-info {
      display: flex;
      flex-direction: column;
      gap: 1px;
    }
    .brand-title {
      font-size: 15.5px;
      font-weight: 700;
      color: var(--text-heading);
      letter-spacing: -0.2px;
    }
    .brand-version-wrap {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .brand-version {
      font-size: 11px;
      color: var(--accent-cyan);
      font-family: var(--font-mono);
      font-weight: 600;
      letter-spacing: 0.3px;
    }
    .brand-pill {
      font-size: 10px;
      font-weight: 700;
      padding: 1px 6px;
      border-radius: 4px;
      background-color: var(--accent-subtle);
      color: var(--accent-cyan);
      border: 1px solid rgba(2, 132, 199, 0.3);
      font-family: var(--font-mono);
      text-transform: uppercase;
    }

    .nav-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    /* Synchronized Topbar Buttons */
    .nav-btn {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 8px 15px;
      font-size: 13px;
      font-weight: 600;
      border-radius: var(--radius-sm);
      text-decoration: none;
      transition: all 0.15s ease;
      cursor: pointer;
      font-family: var(--font-sans);
      white-space: nowrap;
    }

    .nav-btn-primary {
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: #ffffff !important;
      border: 1px solid rgba(56, 189, 248, 0.4);
      box-shadow: 0 2px 10px rgba(2, 132, 199, 0.3);
    }
    .nav-btn-primary:hover {
      background: linear-gradient(135deg, #0369a1 0%, #075985 100%);
      box-shadow: 0 4px 14px rgba(2, 132, 199, 0.5);
      transform: translateY(-1px);
    }

    .nav-btn-outline {
      background-color: var(--bg-card);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
    }
    .nav-btn-outline:hover {
      background-color: var(--bg-surface-hover);
      border-color: var(--border-light);
      color: var(--accent-cyan);
    }

    /* Theme Switcher Button matching Image 2 & Main Dashboard */
    .btn-theme-toggle {
      background-color: var(--bg-card);
      color: var(--text-primary);
      border: 1px solid var(--border-color);
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 8px 14px;
      font-size: 12.5px;
      font-weight: 600;
      border-radius: var(--radius-sm);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-theme-toggle:hover {
      background-color: var(--bg-surface-hover);
      border-color: var(--border-light);
      box-shadow: 0 0 10px var(--accent-glow);
    }

    .health-pulse-dot {
      width: 8px;
      height: 8px;
      background-color: var(--status-success);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--status-success);
      display: inline-block;
      animation: pulseGreen 2s infinite;
    }
    @keyframes pulseGreen {
      0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
      70% { transform: scale(1.1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
      100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* ══════════════════════════════════════════════════════════════════
       HERO OVERVIEW CARD (CYBER COMMAND CONSOLE)
       ══════════════════════════════════════════════════════════════════ */
    .docs-hero {
      max-width: 1360px;
      margin: 28px auto 0 auto;
      padding: 0 24px;
    }
    .hero-card {
      background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-card-secondary) 100%);
      border: 1px solid var(--border-color);
      border-top: 3px solid var(--accent);
      border-radius: var(--radius-lg);
      padding: 24px 28px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
      position: relative;
      overflow: hidden;
    }
    .hero-card::after {
      content: "";
      position: absolute;
      top: 0;
      right: 0;
      width: 300px;
      height: 100%;
      background: radial-gradient(circle at 100% 0%, rgba(2, 132, 199, 0.12) 0%, transparent 70%);
      pointer-events: none;
    }

    .hero-header-row {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      flex-wrap: wrap;
    }
    .hero-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-heading);
      margin: 0 0 8px 0;
      letter-spacing: -0.3px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .hero-title-icon {
      width: 32px;
      height: 32px;
      background: var(--accent-subtle);
      border: 1px solid var(--border-light);
      border-radius: 8px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      color: var(--accent-cyan);
    }
    .hero-desc {
      font-size: 14.5px;
      color: var(--text-secondary);
      margin: 0;
      max-width: 950px;
      line-height: 1.6;
    }

    .hero-badges {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 20px;
      align-items: center;
    }
    .hero-badge {
      font-size: 11.5px;
      font-weight: 600;
      padding: 4px 11px;
      border-radius: var(--radius-sm);
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      color: var(--text-secondary);
      font-family: var(--font-mono);
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .hero-badge.badge-owasp {
      border-color: rgba(2, 132, 199, 0.4);
      background-color: var(--accent-subtle);
      color: var(--accent-cyan);
    }
    .hero-badge.badge-atlas {
      border-color: rgba(245, 158, 11, 0.4);
      background-color: rgba(245, 158, 11, 0.12);
      color: #fbbf24;
    }
    .hero-badge.badge-live {
      border-color: rgba(16, 185, 129, 0.4);
      background-color: rgba(16, 185, 129, 0.12);
      color: #34d399;
    }

    /* ══════════════════════════════════════════════════════════════════
       SWAGGER UI SOLID CYBER SOC OVERRIDES
       ══════════════════════════════════════════════════════════════════ */
    .swagger-ui {
      max-width: 1360px !important;
      margin: 0 auto !important;
      padding: 24px 24px 80px 24px !important;
      font-family: var(--font-sans) !important;
    }

    .swagger-ui .topbar { display: none !important; }
    .swagger-ui .information-container { display: none !important; }

    /* Servers selection block */
    .swagger-ui .scheme-container {
      background-color: var(--bg-card) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: var(--radius-md) !important;
      padding: 16px 20px !important;
      margin-bottom: 24px !important;
      box-shadow: none !important;
    }
    .swagger-ui .servers-title {
      color: var(--text-heading) !important;
      font-size: 13.5px !important;
      font-weight: 700 !important;
      margin-bottom: 8px !important;
      letter-spacing: 0.3px;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }
    .swagger-ui .servers select {
      background-color: var(--bg-input) !important;
      color: var(--text-primary) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: var(--radius-sm) !important;
      padding: 8px 16px !important;
      font-size: 13.5px !important;
      font-family: var(--font-mono) !important;
      outline: none !important;
      transition: border-color 0.2s ease;
    }
    .swagger-ui .servers select:focus {
      border-color: var(--accent) !important;
      box-shadow: 0 0 8px var(--accent-glow) !important;
    }

    /* Filter operation input */
    .swagger-ui .filter .operation-filter-input {
      background-color: var(--bg-card) !important;
      color: var(--text-heading) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: var(--radius-md) !important;
      padding: 12px 18px !important;
      font-size: 14px !important;
      margin: 0 0 24px 0 !important;
      box-shadow: none !important;
      transition: all 0.2s ease;
      font-family: var(--font-sans) !important;
    }
    .swagger-ui .filter .operation-filter-input:focus {
      border-color: var(--accent) !important;
      background-color: var(--bg-surface) !important;
      box-shadow: 0 0 12px var(--accent-glow) !important;
    }

    /* Section Tag Group Header */
    .swagger-ui .opblock-tag {
      color: var(--text-heading) !important;
      font-size: 18px !important;
      font-weight: 700 !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 18px 0 12px 0 !important;
      margin-bottom: 16px !important;
      letter-spacing: -0.2px;
      display: flex !important;
      align-items: baseline !important;
      gap: 12px !important;
    }
    .swagger-ui .opblock-tag small {
      color: var(--text-secondary) !important;
      font-size: 13.5px !important;
      font-weight: 400 !important;
      line-height: 1.5;
    }

    /* Operation Blocks - Flat Cyber Cards */
    .swagger-ui .opblock {
      background-color: var(--bg-card) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: var(--radius-md) !important;
      margin-bottom: 12px !important;
      box-shadow: none !important;
      overflow: hidden;
      transition: border-color 0.15s ease, background-color 0.15s ease;
    }
    .swagger-ui .opblock:hover {
      border-color: var(--border-light) !important;
    }

    .swagger-ui .opblock .opblock-summary {
      padding: 10px 18px !important;
      border-bottom: 1px solid transparent !important;
    }
    .swagger-ui .opblock.is-open .opblock-summary {
      border-bottom-color: var(--border-color) !important;
    }

    .swagger-ui .opblock .opblock-summary-method {
      border-radius: var(--radius-sm) !important;
      font-size: 12px !important;
      font-weight: 800 !important;
      padding: 6px 14px !important;
      min-width: 82px !important;
      text-align: center !important;
      font-family: var(--font-mono) !important;
      letter-spacing: 0.5px;
      text-shadow: 0 1px 2px rgba(0,0,0,0.4);
    }

    /* Solid Method Badges Synchronized with System Colors */
    .swagger-ui .opblock.opblock-get .opblock-summary-method {
      background: linear-gradient(135deg, #0284c7, #0369a1) !important;
      color: #ffffff !important;
    }
    .swagger-ui .opblock.opblock-post .opblock-summary-method {
      background: linear-gradient(135deg, #10b981, #059669) !important;
      color: #ffffff !important;
    }
    .swagger-ui .opblock.opblock-delete .opblock-summary-method {
      background: linear-gradient(135deg, #ef4444, #dc2626) !important;
      color: #ffffff !important;
    }
    .swagger-ui .opblock.opblock-put .opblock-summary-method {
      background: linear-gradient(135deg, #f59e0b, #d97706) !important;
      color: #ffffff !important;
    }

    .swagger-ui .opblock .opblock-summary-path a span {
      color: var(--text-heading) !important;
      font-size: 14px !important;
      font-family: var(--font-mono) !important;
      font-weight: 600 !important;
    }

    .swagger-ui .opblock .opblock-summary-description {
      color: var(--text-secondary) !important;
      font-size: 13.5px !important;
    }

    /* Text & Content Elements Inside Accordion */
    .swagger-ui .opblock-body {
      background-color: var(--bg-surface) !important;
      padding: 24px !important;
    }
    .swagger-ui .markdown p,
    .swagger-ui .markdown li,
    .swagger-ui .opblock-description-wrapper p,
    .swagger-ui .responses-inner h4,
    .swagger-ui .responses-inner h5,
    .swagger-ui .response-col_status,
    .swagger-ui .response-col_description,
    .swagger-ui .response-col_links,
    .swagger-ui .parameter__in,
    .swagger-ui .opblock-body p,
    .swagger-ui table thead tr td,
    .swagger-ui table tbody tr td {
      color: var(--text-body) !important;
    }

    .swagger-ui .opblock-section-header {
      background-color: transparent !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 12px 0 !important;
      margin-bottom: 16px !important;
    }
    .swagger-ui .opblock-section-header h4 {
      color: var(--text-heading) !important;
      font-size: 14px !important;
      font-weight: 700 !important;
      letter-spacing: 0.3px;
    }

    .swagger-ui table thead tr th {
      color: var(--text-muted) !important;
      font-size: 12px !important;
      font-weight: 700 !important;
      text-transform: uppercase !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 12px 8px !important;
      font-family: var(--font-mono);
    }
    .swagger-ui table tbody tr td {
      color: var(--text-body) !important;
      font-size: 13.5px !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 12px 8px !important;
    }

    .swagger-ui .parameter__name {
      color: var(--text-heading) !important;
      font-weight: 700 !important;
      font-family: var(--font-mono) !important;
      font-size: 13px !important;
    }
    .swagger-ui .parameter__type {
      color: var(--accent-cyan) !important;
      font-size: 12px !important;
      font-family: var(--font-mono) !important;
    }

    /* Buttons inside Swagger UI */
    .swagger-ui .btn {
      border-radius: var(--radius-sm) !important;
      font-size: 13px !important;
      font-weight: 600 !important;
      padding: 8px 16px !important;
      border: 1px solid var(--border-color) !important;
      background-color: var(--bg-card) !important;
      color: var(--text-body) !important;
      box-shadow: none !important;
      transition: all 0.15s ease !important;
    }
    .swagger-ui .btn:hover {
      background-color: var(--bg-surface-hover) !important;
      border-color: var(--border-light) !important;
    }
    .swagger-ui .btn.execute {
      background: linear-gradient(135deg, #0284c7, #0369a1) !important;
      color: #ffffff !important;
      border-color: rgba(56, 189, 248, 0.4) !important;
    }
    .swagger-ui .btn.cancel {
      background-color: transparent !important;
      color: #ef4444 !important;
      border-color: #ef4444 !important;
    }

    /* Code Blocks & JSON Previews */
    .swagger-ui .highlight-code,
    .swagger-ui pre {
      background-color: var(--code-bg) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: var(--radius-md) !important;
      color: #38bdf8 !important;
      font-family: var(--font-mono) !important;
      font-size: 13px !important;
      padding: 16px !important;
    }
    .swagger-ui pre code {
      color: #e2e8f0 !important;
      font-family: var(--font-mono) !important;
    }

    .swagger-ui svg {
      fill: var(--text-secondary) !important;
    }

    /* Responsive mobile breakpoint */
    @media (max-width: 768px) {
      .docs-nav { padding: 0 16px; }
      .brand-version-wrap { display: none; }
      .hero-badges { display: none; }
      .nav-btn span { display: none; }
      .nav-btn { padding: 8px 10px; }
    }
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <nav class="docs-nav">
    <a href="/" class="nav-brand" title="Return to Main Command Dashboard">
      <div class="sidebar-brand-logo-wrap">
        <img src="/static/logo.jpg" alt="Logo" class="sidebar-brand-logo">
        <span class="logo-status-indicator" title="System Online"></span>
      </div>
      <div class="brand-info">
        <div class="brand-title">AI Security Scanner</div>
        <div class="brand-version-wrap">
          <span class="brand-version">v2.0 Enterprise</span>
          <span class="brand-pill">REST API</span>
        </div>
      </div>
    </a>

    <div class="nav-actions">
      <!-- Synchronized Theme Toggle Button with Sun/Moon SVGs -->
      <button class="btn-theme-toggle" id="btn-theme-toggle" onclick="toggleTheme()" title="Switch Light/Dark Theme">
        <span id="theme-btn-icon" style="display:inline-flex;align-items:center;justify-content:center"></span>
        <span id="theme-btn-label">Theme: Dark</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </button>

      <!-- Back to Dashboard with Icon -->
      <a href="/" class="nav-btn nav-btn-primary" title="Return to Main Command Dashboard">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
        <span>Back to Dashboard</span>
      </a>

      <!-- OpenAPI Spec Download Link -->
      <a href="/api/openapi.json" target="_blank" class="nav-btn nav-btn-outline" title="Open Raw OpenAPI 3.0 JSON Specification">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
        <span>OpenAPI JSON</span>
      </a>

      <!-- System Diagnostic Telemetry Link -->
      <a href="/api/health" target="_blank" class="nav-btn nav-btn-outline" title="View System Diagnostic Telemetry">
        <span class="health-pulse-dot"></span>
        <span>Health Check</span>
      </a>
    </div>
  </nav>

  <!-- Hero Overview Card -->
  <header class="docs-hero">
    <div class="hero-card">
      <div class="hero-header-row">
        <div>
          <div class="hero-title">
            <span class="hero-title-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            </span>
            REST API Specification & Testing Console
          </div>
          <p class="hero-desc">
            Production-grade OpenAPI 3.0 specification and interactive security testing console for the AI Security Scanner framework.
            Equipped with real-time SSE telemetry, Bearer JWT authentication, and full compliance alignment with OWASP Top 10 for LLMs 2025 and MITRE ATLAS Matrix.
          </p>
        </div>
      </div>

      <div class="hero-badges">
        <span class="hero-badge badge-owasp">🛡️ OWASP LLM 2025</span>
        <span class="hero-badge badge-atlas">🎯 MITRE ATLAS Matrix</span>
        <span class="hero-badge">🔑 Bearer JWT Auth</span>
        <span class="hero-badge">📊 Prometheus Telemetry</span>
        <span class="hero-badge">⚡ Server-Sent Events (SSE)</span>
        <span class="hero-badge badge-live"><span class="health-pulse-dot" style="width:6px;height:6px"></span> Engine Status: Operational</span>
      </div>
    </div>
  </header>

  <!-- Swagger UI Mount Point -->
  <div id="swagger-ui"></div>

  <script src="/static/swagger-ui-bundle.js"></script>
  <script>
    // Exact Sun and Moon SVGs synchronized with index.html
    const sunSvg = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 5px rgba(245, 158, 11, 0.6))"><circle cx="12" cy="12" r="4.5" fill="#fef3c7"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
    const moonSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="filter:drop-shadow(0 0 4px rgba(56, 189, 248, 0.5))"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;

    function initTheme() {
      const savedTheme = localStorage.getItem('ai_scanner_theme') || 'dark';
      applyTheme(savedTheme);
    }

    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('ai_scanner_theme', theme);
      const label = document.getElementById('theme-btn-label');
      const iconWrap = document.getElementById('theme-btn-icon');
      const btn = document.getElementById('btn-theme-toggle');

      if (theme === 'light') {
        if (iconWrap) iconWrap.innerHTML = sunSvg;
        if (label) label.textContent = 'Theme: Light';
        if (btn) btn.title = 'Switch to Dark Theme';
      } else {
        if (iconWrap) iconWrap.innerHTML = moonSvg;
        if (label) label.textContent = 'Theme: Dark';
        if (btn) btn.title = 'Switch to Light Theme';
      }
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    }

    window.onload = function() {
      initTheme();
      window.ui = SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout",
        defaultModelsExpandDepth: -1,
        docExpansion: "list",
        filter: true,
        showExtensions: true,
        showCommonExtensions: true
      });
    };
  </script>
</body>
</html>
"""

def get_openapi_spec() -> dict:
    """Returns the complete, fully localized OpenAPI 3.0 specification dictionary."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "AI Security Scanner REST API",
            "description": "Production-grade RESTful API for AI Red-Teaming, Automated Vulnerability Assessment, and OWASP Top 10 for LLMs 2025 Auditing.",
            "version": "2.0.0",
            "contact": {
                "name": "AI Security Research Lab",
                "url": "https://github.com/your-org/AI_Security_Scanner"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {"url": "http://localhost:5000", "description": "Local development server"}
        ],
        "tags": [
            {
                "name": "System & Health",
                "description": "System health verification, Prometheus telemetry metrics, and runtime observability."
            },
            {
                "name": "Authentication & Config",
                "description": "JWT Bearer token issuance, API key validation, and target LLM configuration."
            },
            {
                "name": "Scanning & Exploitation",
                "description": "Trigger security scan modules, stream real-time execution logs (SSE), and cancel active assessments."
            },
            {
                "name": "Findings & Analytics",
                "description": "Query identified LLM vulnerabilities, CVSS v3.1 risk scores, execution history, and date filters."
            },
            {
                "name": "Threat Modeling & Benchmarks",
                "description": "MITRE ATLAS attack surface profiling, automated threat modeling, and HarmBench / safety benchmarks."
            },
            {
                "name": "Audit Reports & Export",
                "description": "Compile, render, and download executive HTML compliance reports and structured JSON audit data."
            }
        ],
        "paths": {
            "/api/health": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "System Health & Diagnostics (Health Check)",
                    "description": "Check SQLite database connection status, background worker thread state, active module, and framework version.",
                    "responses": {
                        "200": {
                            "description": "System operational status (healthy or degraded)",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "status": "healthy",
                                        "database": "connected",
                                        "scanner_running": False,
                                        "active_module": None,
                                        "timestamp": "2026-10-14T21:15:00",
                                        "version": "2.0.0"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/metrics": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Operation & Findings Telemetry in JSON",
                    "description": "Provides total scan counts, finding distribution grouped by severity, and scanner uptime.",
                    "responses": {
                        "200": {"description": "JSON operational metrics and telemetry"}
                    }
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Prometheus Scraping Exporter",
                    "description": "Exports metrics in standard Prometheus text/plain format for scraping by Prometheus Server and Grafana dashboards.",
                    "responses": {
                        "200": {
                            "description": "Standard Prometheus text/plain telemetry",
                            "content": {"text/plain": {}}
                        }
                    }
                }
            },
            "/api/auth/login": {
                "post": {
                    "tags": ["Authentication & Config"],
                    "summary": "Administrative Authentication & Bearer JWT Issuance",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "api_key": {"type": "string", "example": "ai-scanner-admin-secret-token"},
                                        "username": {"type": "string", "example": "admin"},
                                        "password": {"type": "string", "example": "ai-scanner-admin-secret-token"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Authentication successful; returns 24-hour valid JWT Bearer token"},
                        "401": {"description": "Invalid credentials provided"}
                    }
                }
            },
            "/api/config": {
                "get": {
                    "tags": ["Authentication & Config"],
                    "summary": "Retrieve Default Target LLM Configuration",
                    "description": "Returns current target URL, target model ID, request timeout, and API key mask.",
                    "responses": {
                        "200": {"description": "Current target configuration parameters"}
                    }
                },
                "post": {
                    "tags": ["Authentication & Config"],
                    "summary": "Update Target LLM Configuration",
                    "description": "Saves new target endpoint URL, model name, timeout, and API authentication credentials.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "target_url": {"type": "string", "example": "http://localhost:11434"},
                                        "target_model": {"type": "string", "example": "llama3"},
                                        "timeout": {"type": "integer", "example": 60},
                                        "api_key": {"type": "string", "example": "sk-target-api-key"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Target configuration successfully updated"}
                    }
                }
            },
            "/api/connection/test": {
                "post": {
                    "tags": ["Authentication & Config"],
                    "summary": "Test Target LLM Connectivity",
                    "description": "Sends a minimal ping query to verify that the target inference endpoint is reachable and responsive.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "target_url": {"type": "string", "example": "http://localhost:11434"},
                                        "target_model": {"type": "string", "example": "llama3"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Connection test result with latency and model status"}
                    }
                }
            },
            "/api/modules": {
                "get": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "List All Registered Attack Modules",
                    "description": "Returns metadata for all loaded exploit modules (OWASP Top 10 2025, MITRE ATLAS, payload counts, severity ratings).",
                    "responses": {
                        "200": {"description": "Dictionary of registered attack modules"}
                    }
                }
            },
            "/api/modules/{module_name}/payloads": {
                "get": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Retrieve Testcase Payloads for a Specific Module",
                    "parameters": [
                        {"name": "module_name", "in": "path", "required": True, "schema": {"type": "string"}, "description": "Module identifier (e.g., prompt_injection, jailbreak)"}
                    ],
                    "responses": {
                        "200": {"description": "List of adversarial testcase prompts and categories"}
                    }
                }
            },
            "/api/scan/run": {
                "post": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Launch Targeted Security Scan for a Single Module",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["module", "target_url", "target_model"],
                                    "properties": {
                                        "module": {"type": "string", "example": "jailbreak", "description": "Attack module name"},
                                        "target_url": {"type": "string", "example": "http://localhost:11434", "description": "Target LLM inference endpoint URL"},
                                        "target_model": {"type": "string", "example": "llama3", "description": "Target LLM model ID"},
                                        "timeout": {"type": "integer", "example": 60, "description": "Request timeout in seconds"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Scan session initiated successfully"},
                        "400": {"description": "Invalid parameters or unknown module"},
                        "409": {"description": "A scan is already actively running"}
                    }
                }
            },
            "/api/scan/run-all": {
                "post": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Launch Comprehensive Multi-Module Scan Assessment",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "modules": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "example": ["prompt_injection", "jailbreak", "rag_security", "excessive_agency"]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Batch scan assessment sequence initiated"}
                    }
                }
            },
            "/api/scan/cancel": {
                "post": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Cancel Running Scan Session",
                    "description": "Signals the active worker thread to stop evaluating further payloads and terminate cleanly.",
                    "responses": {
                        "200": {"description": "Cancellation signal received"}
                    }
                }
            },
            "/api/scan/status": {
                "get": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Query Live Scan Status & Progress",
                    "description": "Returns execution percentage, active module, total completed tests, and findings count.",
                    "responses": {
                        "200": {"description": "Live scanner state and progress percentage"}
                    }
                }
            },
            "/api/scan/stream": {
                "get": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Real-Time Terminal Log Stream (Server-Sent Events)",
                    "description": "Establishes an HTTP SSE connection to stream real-time telemetry and test output as payloads execute.",
                    "responses": {
                        "200": {
                            "description": "SSE text/event-stream connection",
                            "content": {"text/event-stream": {}}
                        }
                    }
                }
            },
            "/api/findings": {
                "get": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Query Identified Vulnerabilities with Filters",
                    "parameters": [
                        {"name": "severity", "in": "query", "schema": {"type": "string"}, "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"},
                        {"name": "module", "in": "query", "schema": {"type": "string"}, "description": "Filter by attack module identifier"},
                        {"name": "date", "in": "query", "schema": {"type": "string"}, "description": "Filter by creation date (YYYY-MM-DD)"},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}, "description": "Maximum records to return"}
                    ],
                    "responses": {
                        "200": {"description": "List of findings matching criteria and available assessment dates"}
                    }
                },
                "delete": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Clear All Findings from Database",
                    "description": "Permanently deletes all recorded vulnerabilities and resets findings telemetry.",
                    "responses": {
                        "200": {"description": "Findings database cleared"}
                    }
                }
            },
            "/api/findings/replay": {
                "post": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Replay Adversarial Testcase Against Target",
                    "description": "Re-sends the exact exploit prompt from a recorded finding to determine whether defensive remediation was effective.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["finding_id"],
                                    "properties": {
                                        "finding_id": {"type": "integer", "example": 14}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Replay outcome indicating if finding remains exploitable or is mitigated"}
                    }
                }
            },
            "/api/scans": {
                "get": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Query Assessment Session History",
                    "parameters": [
                        {"name": "date", "in": "query", "schema": {"type": "string"}, "description": "Filter by date (YYYY-MM-DD)"},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}}
                    ],
                    "responses": {
                        "200": {"description": "Chronological history of security assessment sessions"}
                    }
                }
            },
            "/api/stats": {
                "get": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Dashboard Analytics & CVSS Risk Score Aggregations",
                    "description": "Computes severity counts, findings grouped by module, attack module severity matrix, and overall threat audit score.",
                    "responses": {
                        "200": {"description": "Aggregated dashboard statistics"}
                    }
                }
            },
            "/api/taxonomy": {
                "get": {
                    "tags": ["Threat Modeling & Benchmarks"],
                    "summary": "Query Security Taxonomies (OWASP LLM & MITRE ATLAS)",
                    "description": "Returns hierarchical mapping data of OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS matrix tactics/techniques.",
                    "responses": {
                        "200": {"description": "Taxonomy definitions and cross-framework mappings"}
                    }
                }
            },
            "/api/threat-model": {
                "post": {
                    "tags": ["Threat Modeling & Benchmarks"],
                    "summary": "Generate Automated Threat Model & Architecture Profiling",
                    "description": "Analyzes the specified target LLM architecture, external tool integrations, and RAG context to formulate a customized MITRE ATLAS threat model.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "system_name": {"type": "string", "example": "Enterprise AI Assistant"},
                                        "architecture": {"type": "string", "example": "rag_agent"},
                                        "data_sensitivity": {"type": "string", "example": "confidential"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Generated MITRE ATLAS threat model and mitigation recommendations"}
                    }
                }
            },
            "/api/benchmark/run": {
                "post": {
                    "tags": ["Threat Modeling & Benchmarks"],
                    "summary": "Execute Standardized Adversarial Benchmark",
                    "description": "Executes HarmBench subsets, Vietnamese LLM safety benchmarks, or standard red-teaming datasets.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["benchmark_type"],
                                    "properties": {
                                        "benchmark_type": {"type": "string", "example": "harmbench_subset", "description": "harmbench_subset or vietnamese_benchmark"},
                                        "target_url": {"type": "string", "example": "http://localhost:11434"},
                                        "target_model": {"type": "string", "example": "llama3"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Benchmark evaluation started"}
                    }
                }
            },
            "/api/report/generate": {
                "post": {
                    "tags": ["Audit Reports & Export"],
                    "summary": "Generate Executive Security Assessment Report",
                    "description": "Compiles all findings, risk scores, and OWASP compliance evaluations into a formal audit report.",
                    "responses": {
                        "200": {"description": "Report generated with file paths"}
                    }
                }
            },
            "/api/report/view": {
                "get": {
                    "tags": ["Audit Reports & Export"],
                    "summary": "Render Interactive HTML Audit Report",
                    "responses": {
                        "200": {
                            "description": "Interactive HTML security report view",
                            "content": {"text/html": {}}
                        }
                    }
                }
            },
            "/api/report/download": {
                "get": {
                    "tags": ["Audit Reports & Export"],
                    "summary": "Download Standalone HTML Security Report",
                    "responses": {
                        "200": {
                            "description": "Downloadable HTML file attachment",
                            "content": {"text/html": {}}
                        }
                    }
                }
            },
            "/api/report/json": {
                "get": {
                    "tags": ["Audit Reports & Export"],
                    "summary": "Export Audit Findings & Telemetry in JSON Format",
                    "responses": {
                        "200": {"description": "Raw findings, CVSS calculations, and system metadata in JSON"}
                    }
                }
            },
            "/api/integrations/status": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Check Inference Engine Integrations Status",
                    "description": "Checks connectivity with local and remote inference runtimes such as Ollama, vLLM, and LangChain agents.",
                    "responses": {
                        "200": {"description": "Operational status of supported AI integrations"}
                    }
                }
            }
        }
    }
