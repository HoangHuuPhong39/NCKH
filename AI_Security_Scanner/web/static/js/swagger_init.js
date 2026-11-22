// Exact Sun and Moon SVGssynchronized with index.html
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
