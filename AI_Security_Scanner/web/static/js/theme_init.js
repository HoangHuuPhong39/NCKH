// Immediate Theme Initialization to avoid white flash (shared by Dashboard & Swagger Docs)
(function() {
  try {
    const saved = localStorage.getItem('ai_scanner_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
  } catch (e) {}
})();
