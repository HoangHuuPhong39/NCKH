/**
 * AI Security Scanner - i18n (Internationalization) System
 * Hệ thống đa ngôn ngữ Tiếng Việt / English
 */

// Translation Dictionary - Từ điển dịch thuật
const translations = {
  vi: {
    // Navigation & Menu
    nav_group_test: "Kiểm thử & Đánh giá",
    nav_scan: "Scan Control",
    nav_threatmodel: "Threat Model",
    nav_findings: "Findings",
    nav_group_analytics: "Phân tích & Thực nghiệm",
    nav_dashboard: "Dashboard",
    nav_benchmark: "Benchmark & OSS",
    nav_remediation: "Remediation",
    nav_reports: "Reports",
    nav_group_config: "Cấu hình & Quản trị",
    nav_taxonomy: "Taxonomy",
    nav_settings: "Settings",
    nav_apidocs: "API Docs",
    
    // Topbar Actions
    test_ping: "Test Ping",
    export_html: "Export HTML",
    export_json: "Export JSON",
    print_pdf: "Print / PDF",
    refresh: "Refresh",
    theme_dark: "Theme: Dark",
    theme_light: "Theme: Light",
    
    // Scan Control Page
    page_title_scan: "Scan Control",
    page_title_findings: "Security Findings",
    page_title_dashboard: "Dashboard & Analytics",
    page_title_remediation: "Remediation Guidance",
    page_title_report: "Audit Reports",
    page_title_taxonomy: "Taxonomy Browser",
    page_title_settings: "System Settings",
    page_title_threatmodel: "Threat Model & System Profiler",
    page_title_benchmark: "Benchmark & OSS Wrappers",
    
    banner_title: "AI Security Scanner",
    banner_subtitle: "Đánh giá và phát hiện lỗ hổng bảo mật trong các ứng dụng LLM",
    banner_tagline1: "Safer AI",
    banner_tagline2: "Stronger Tomorrow",
    
    // Configuration Card
    card_config_title: "Cấu hình quét hệ thống",
    card_config_subtitle: "Cung cấp thông tin endpoint và tham số để bắt đầu quét",
    btn_start_scan: "Bắt đầu quét",
    btn_save_config: "Lưu cấu hình",
    btn_test_connection: "Test Connection",
    
    label_target_url: "Target URL",
    label_target_model: "Target Model",
    label_timeout: "Timeout (sec)",
    label_api_key: "API Key (Optional)",
    
    // Module Selection Card
    card_modules_title: "Chọn module kiểm thử",
    card_modules_subtitle: "Chọn các module tấn công và đánh giá để thực thi",
    modules_selected: "đã chọn",
    btn_select_all: "Chọn tất cả",
    btn_deselect_all: "Bỏ chọn tất cả",
    btn_edit_payloads: "Tùy chỉnh payloads",
    btn_run_selected: "Chạy đã chọn",
    btn_run_all: "Chạy toàn bộ 14 Modules",
    btn_stop_scan: "Dừng quét",
    adaptive_mode: "Adaptive Mutation (13 Strategies)",
    scan_ready: "Sẵn sàng thực thi.",
    
    // Terminal Card
    card_terminal_title: "Nhật ký thực thi (Realtime)",
    card_terminal_subtitle: "Theo dõi tiến trình quét và kết quả theo thời gian thực",
    latency: "Latency",
    live: "Live",
    auto_scroll: "Auto-scroll",
    copy_log: "Copy Log",
    clear_log: "Xóa log",
    progress_waiting: "Chờ thực thi",
    
    // Findings Page
    findings_title: "Security Assessment Findings",
    findings_subtitle: "Toàn bộ các lỗ hổng bảo mật và vi phạm chính sách an toàn AI được phát hiện",
    btn_refresh: "Làm mới",
    btn_clear_history: "Xóa lịch sử",
    filter_all: "All",
    filter_critical: "Critical",
    filter_high: "High",
    filter_medium: "Medium",
    filter_low: "Low",
    filter_info: "Info",
    search_placeholder: "Tìm kiếm payload, phản hồi, target...",
    
    // Table Headers
    th_index: "#",
    th_module: "Module",
    th_severity: "Severity",
    th_risk_score: "Risk Score",
    th_owasp_mitre: "OWASP / MITRE",
    th_payload: "Payload Preview",
    th_response: "AI Response Preview",
    th_timestamp: "Timestamp",
    
    // Dashboard
    dash_total_logs: "Total System Logs",
    dash_new_findings: "New Findings",
    dash_active_modules: "Active Modules",
    dash_target_latency: "Target Latency",
    dash_threat_audit: "THREAT AUDIT",
    dash_total_findings: "TOTAL FINDINGS",
    dash_critical_risks: "CRITICAL RISKS",
    dash_high_severity: "HIGH SEVERITY",
    dash_medium_severity: "MEDIUM SEVERITY",
    dash_low_info: "LOW / INFO",
    dash_findings_by_module: "Findings by Attack Module",
    dash_security_posture: "Security Posture & Compliance",
    dash_incident_correlator: "Security Incident Correlator",
    dash_system_health: "System Runtime & Health",
    dash_quick_actions: "Operational Quick Actions",
    dash_log_stream: "Operational Log Stream & Telemetry",
    dash_scan_history: "Assessment Execution History",
    
    // Remediation
    remediation_title: "Defensive Remediation & Hardening Guidance",
    remediation_subtitle: "Chiến lược giảm thiểu rủi ro và tăng cường bảo mật phân nhóm theo OWASP LLM 2025",
    btn_expand_all: "Mở rộng tất cả",
    
    // Reports
    report_title: "Audit Report Compilation & Export",
    report_subtitle: "Biên dịch báo cáo kiểm thử an toàn AI, xuất file HTML/JSON hoặc in ấn chuẩn báo cáo",
    btn_compile_report: "Compile HTML Report",
    report_export_note: "Tải file HTML/JSON hoặc In PDF bằng các nút thao tác trên thanh menu chính",
    
    // Taxonomy
    taxonomy_title: "AI Security Testing Taxonomy (OWASP LLM 2025 & MITRE ATLAS)",
    taxonomy_subtitle: "Phân loại cấu trúc phân tầng các kỹ thuật, chiến thuật tấn công và lỗ hổng AI/LLM",
    btn_refresh_taxonomy: "Làm mới Taxonomy",
    
    // Settings
    settings_env_title: "Environment & Service Parameters",
    settings_engine_title: "Engine Specifications",
    btn_save_settings: "Save Configuration",
    
    // Threat Model
    threatmodel_title: "AI System Profiler & Threat Modeling (MITRE ATLAS & OWASP 2025)",
    threatmodel_subtitle: "Tự động nhận diện kiến trúc mục tiêu (LLM / RAG / Agent / ML Model) và phân tích đa tầng bề mặt tấn công",
    btn_analyze_surface: "Analyze Target Surface",
    
    // Benchmark
    benchmark_title: "Thực Nghiệm Định Lượng & Bộ Benchmark Tiếng Việt (62 Kịch Bản)",
    benchmark_subtitle: "Đánh giá độ chính xác (Precision, Recall, F1-Score, ASR) và kiểm định khoảng cách an toàn ngôn ngữ (Cross-lingual Gap)",
    btn_bm_vietnamese: "Chạy Benchmark Tiếng Việt (62 Cases)",
    btn_bm_standard: "Chạy Benchmark Chuẩn (36 Cases)",
    btn_bm_harmbench: "Chạy HarmBench Subset (10 Cases)",
    oss_title: "Liên Minh 6 Công Cụ Kiểm Thử Mã Nguồn Mở Quốc Tế (Integration Wrappers)",
    oss_subtitle: "Tích hợp đồng nhất NVIDIA Garak, Microsoft PyRIT, Promptfoo, DeepTeam, Giskard OSS và IBM ART",
    btn_check_status: "Kiểm tra Trạng thái",
    
    // Modal
    modal_finding_detail: "Finding Detail",
    modal_close: "Close",
    modal_replay: "Replay Test (Verify Reproducibility)",
    modal_copy_payload: "Copy Payload",
    modal_copy_response: "Copy Response",
    
    // Common Buttons
    btn_close: "Close",
    btn_cancel: "Cancel",
    btn_save: "Save",
    btn_apply: "Apply",
    btn_delete: "Delete",
    btn_edit: "Edit",
    btn_add: "Add",
    btn_remove: "Remove",
    btn_reset: "Reset",
    
    // Status Messages
    status_connected: "Connected",
    status_disconnected: "Disconnected",
    status_checking: "Checking...",
    status_loading: "Loading...",
    status_ready: "Ready",
    status_running: "Running",
    status_completed: "Completed",
    status_failed: "Failed",
    status_healthy: "HEALTHY",
    
    // Toast Messages
    toast_success: "Thành công!",
    toast_error: "Lỗi!",
    toast_info: "Thông báo",
    toast_warning: "Cảnh báo",
    toast_config_saved: "Target settings saved as default.",
    toast_data_refreshed: "Data refreshed.",
    toast_connection_success: "Đã kết nối thành công",
    toast_connection_failed: "Kết nối thất bại",
    
    // Pagination
    pagination_showing: "Hiển thị",
    pagination_of: "của",
    pagination_findings: "findings",
    pagination_rows_per_page: "dòng/trang",
    pagination_page: "Page",
    pagination_first: "First Page",
    pagination_prev: "Previous Page",
    pagination_next: "Next Page",
    pagination_last: "Last Page",
  },
  
  en: {
    // Navigation & Menu
    nav_group_test: "Testing & Assessment",
    nav_scan: "Scan Control",
    nav_threatmodel: "Threat Model",
    nav_findings: "Findings",
    nav_group_analytics: "Analytics & Experiments",
    nav_dashboard: "Dashboard",
    nav_benchmark: "Benchmark & OSS",
    nav_remediation: "Remediation",
    nav_reports: "Reports",
    nav_group_config: "Configuration & Management",
    nav_taxonomy: "Taxonomy",
    nav_settings: "Settings",
    nav_apidocs: "API Docs",
    
    // Topbar Actions
    test_ping: "Test Ping",
    export_html: "Export HTML",
    export_json: "Export JSON",
    print_pdf: "Print / PDF",
    refresh: "Refresh",
    theme_dark: "Theme: Dark",
    theme_light: "Theme: Light",
    
    // Scan Control Page
    page_title_scan: "Scan Control",
    page_title_findings: "Security Findings",
    page_title_dashboard: "Dashboard & Analytics",
    page_title_remediation: "Remediation Guidance",
    page_title_report: "Audit Reports",
    page_title_taxonomy: "Taxonomy Browser",
    page_title_settings: "System Settings",
    page_title_threatmodel: "Threat Model & System Profiler",
    page_title_benchmark: "Benchmark & OSS Wrappers",
    
    banner_title: "AI Security Scanner",
    banner_subtitle: "Assess and detect security vulnerabilities in LLM applications",
    banner_tagline1: "Safer AI",
    banner_tagline2: "Stronger Tomorrow",
    
    // Configuration Card
    card_config_title: "System Scan Configuration",
    card_config_subtitle: "Provide endpoint information and parameters to begin scanning",
    btn_start_scan: "Start Scan",
    btn_save_config: "Save Configuration",
    btn_test_connection: "Test Connection",
    
    label_target_url: "Target URL",
    label_target_model: "Target Model",
    label_timeout: "Timeout (sec)",
    label_api_key: "API Key (Optional)",
    
    // Module Selection Card
    card_modules_title: "Select Testing Modules",
    card_modules_subtitle: "Choose attack and assessment modules to execute",
    modules_selected: "selected",
    btn_select_all: "Select All",
    btn_deselect_all: "Deselect All",
    btn_edit_payloads: "Customize Payloads",
    btn_run_selected: "Run Selected",
    btn_run_all: "Run All 14 Modules",
    btn_stop_scan: "Stop Scan",
    adaptive_mode: "Adaptive Mutation (13 Strategies)",
    scan_ready: "Ready to execute.",
    
    // Terminal Card
    card_terminal_title: "Execution Logs (Realtime)",
    card_terminal_subtitle: "Monitor scan progress and real-time results",
    latency: "Latency",
    live: "Live",
    auto_scroll: "Auto-scroll",
    copy_log: "Copy Log",
    clear_log: "Clear Log",
    progress_waiting: "Waiting to execute",
    
    // Findings Page
    findings_title: "Security Assessment Findings",
    findings_subtitle: "All security vulnerabilities and AI safety policy violations detected",
    btn_refresh: "Refresh",
    btn_clear_history: "Clear History",
    filter_all: "All",
    filter_critical: "Critical",
    filter_high: "High",
    filter_medium: "Medium",
    filter_low: "Low",
    filter_info: "Info",
    search_placeholder: "Search payload, response, target...",
    
    // Table Headers
    th_index: "#",
    th_module: "Module",
    th_severity: "Severity",
    th_risk_score: "Risk Score",
    th_owasp_mitre: "OWASP / MITRE",
    th_payload: "Payload Preview",
    th_response: "AI Response Preview",
    th_timestamp: "Timestamp",
    
    // Dashboard
    dash_total_logs: "Total System Logs",
    dash_new_findings: "New Findings",
    dash_active_modules: "Active Modules",
    dash_target_latency: "Target Latency",
    dash_threat_audit: "THREAT AUDIT",
    dash_total_findings: "TOTAL FINDINGS",
    dash_critical_risks: "CRITICAL RISKS",
    dash_high_severity: "HIGH SEVERITY",
    dash_medium_severity: "MEDIUM SEVERITY",
    dash_low_info: "LOW / INFO",
    dash_findings_by_module: "Findings by Attack Module",
    dash_security_posture: "Security Posture & Compliance",
    dash_incident_correlator: "Security Incident Correlator",
    dash_system_health: "System Runtime & Health",
    dash_quick_actions: "Operational Quick Actions",
    dash_log_stream: "Operational Log Stream & Telemetry",
    dash_scan_history: "Assessment Execution History",
    
    // Remediation
    remediation_title: "Defensive Remediation & Hardening Guidance",
    remediation_subtitle: "Risk mitigation and security enhancement strategies grouped by OWASP LLM 2025",
    btn_expand_all: "Expand All",
    
    // Reports
    report_title: "Audit Report Compilation & Export",
    report_subtitle: "Compile AI safety assessment report, export HTML/JSON file or print standard report",
    btn_compile_report: "Compile HTML Report",
    report_export_note: "Download HTML/JSON file or Print PDF using action buttons in the main menu bar",
    
    // Taxonomy
    taxonomy_title: "AI Security Testing Taxonomy (OWASP LLM 2025 & MITRE ATLAS)",
    taxonomy_subtitle: "Hierarchical classification of techniques, tactics, and AI/LLM vulnerabilities",
    btn_refresh_taxonomy: "Refresh Taxonomy",
    
    // Settings
    settings_env_title: "Environment & Service Parameters",
    settings_engine_title: "Engine Specifications",
    btn_save_settings: "Save Configuration",
    
    // Threat Model
    threatmodel_title: "AI System Profiler & Threat Modeling (MITRE ATLAS & OWASP 2025)",
    threatmodel_subtitle: "Automatically identify target architecture (LLM / RAG / Agent / ML Model) and multi-tier attack surface analysis",
    btn_analyze_surface: "Analyze Target Surface",
    
    // Benchmark
    benchmark_title: "Quantitative Experiments & Vietnamese Benchmark Suite (62 Scenarios)",
    benchmark_subtitle: "Evaluate accuracy (Precision, Recall, F1-Score, ASR) and validate cross-lingual safety gap",
    btn_bm_vietnamese: "Run Vietnamese Benchmark (62 Cases)",
    btn_bm_standard: "Run Standard Benchmark (36 Cases)",
    btn_bm_harmbench: "Run HarmBench Subset (10 Cases)",
    oss_title: "Alliance of 6 International Open-Source Testing Tools (Integration Wrappers)",
    oss_subtitle: "Unified integration of NVIDIA Garak, Microsoft PyRIT, Promptfoo, DeepTeam, Giskard OSS, and IBM ART",
    btn_check_status: "Check Status",
    
    // Modal
    modal_finding_detail: "Finding Detail",
    modal_close: "Close",
    modal_replay: "Replay Test (Verify Reproducibility)",
    modal_copy_payload: "Copy Payload",
    modal_copy_response: "Copy Response",
    
    // Common Buttons
    btn_close: "Close",
    btn_cancel: "Cancel",
    btn_save: "Save",
    btn_apply: "Apply",
    btn_delete: "Delete",
    btn_edit: "Edit",
    btn_add: "Add",
    btn_remove: "Remove",
    btn_reset: "Reset",
    
    // Status Messages
    status_connected: "Connected",
    status_disconnected: "Disconnected",
    status_checking: "Checking...",
    status_loading: "Loading...",
    status_ready: "Ready",
    status_running: "Running",
    status_completed: "Completed",
    status_failed: "Failed",
    status_healthy: "HEALTHY",
    
    // Toast Messages
    toast_success: "Success!",
    toast_error: "Error!",
    toast_info: "Information",
    toast_warning: "Warning",
    toast_config_saved: "Target settings saved as default.",
    toast_data_refreshed: "Data refreshed.",
    toast_connection_success: "Successfully connected",
    toast_connection_failed: "Connection failed",
    
    // Pagination
    pagination_showing: "Showing",
    pagination_of: "of",
    pagination_findings: "findings",
    pagination_rows_per_page: "rows/page",
    pagination_page: "Page",
    pagination_first: "First Page",
    pagination_prev: "Previous Page",
    pagination_next: "Next Page",
    pagination_last: "Last Page",
  }
};

// Current language state
let currentLanguage = 'vi';

/**
 * Initialize i18n system on page load
 */
function initI18n() {
  // Load saved language preference
  const savedLang = localStorage.getItem('ai_scanner_lang');
  if (savedLang && (savedLang === 'vi' || savedLang === 'en')) {
    currentLanguage = savedLang;
  }
  
  // Apply translations
  applyTranslations();
  
  // Update language button UI
  updateLanguageButtonUI();
}

/**
 * Toggle between Vietnamese and English
 */
function toggleLanguage() {
  currentLanguage = (currentLanguage === 'vi') ? 'en' : 'vi';
  
  // Save preference
  localStorage.setItem('ai_scanner_lang', currentLanguage);
  
  // Apply translations
  applyTranslations();
  
  // Update button UI
  updateLanguageButtonUI();
  
  // Show toast notification
  const msg = currentLanguage === 'vi' 
    ? 'Đã chuyển sang Tiếng Việt 🇻🇳' 
    : 'Switched to English 🇺🇸';
  if (typeof showToast === 'function') {
    showToast('info', msg);
  }
}

/**
 * Apply translations to all elements with data-i18n attribute
 */
function applyTranslations() {
  const dict = translations[currentLanguage];
  
  // Translate all elements with data-i18n attribute
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      // Handle different element types
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
        if (el.type === 'button' || el.type === 'submit') {
          el.value = dict[key];
        } else if (el.placeholder !== undefined) {
          el.placeholder = dict[key];
        }
      } else if (el.tagName === 'OPTION') {
        el.textContent = dict[key];
      } else {
        el.textContent = dict[key];
      }
    }
  });
  
  // Special handling for page title
  const currentPage = document.querySelector('.page-view.active');
  if (currentPage) {
    const pageId = currentPage.id.replace('view-', '');
    const titleKey = 'page_title_' + pageId;
    if (dict[titleKey]) {
      const titleEl = document.getElementById('topbar-page-title');
      if (titleEl) {
        titleEl.textContent = dict[titleKey];
      }
    }
  }
}

/**
 * Update language button UI
 */
function updateLanguageButtonUI() {
  const labelEl = document.getElementById('lang-btn-label');
  const btnEl = document.getElementById('btn-lang-toggle');
  
  if (labelEl) {
    labelEl.textContent = currentLanguage === 'vi' ? 'VI 🇻🇳' : 'EN 🇺🇸';
  }
  
  if (btnEl) {
    btnEl.title = currentLanguage === 'vi' 
      ? 'Switch to English / Chuyển sang Tiếng Anh' 
      : 'Chuyển sang Tiếng Việt / Switch to Vietnamese';
  }
}

/**
 * Get translation for a key
 * @param {string} key - Translation key
 * @returns {string} Translated text
 */
function t(key) {
  return translations[currentLanguage][key] || key;
}

/**
 * Set language programmatically
 * @param {string} lang - Language code ('vi' or 'en')
 */
function setLanguage(lang) {
  if (lang !== 'vi' && lang !== 'en') return;
  
  currentLanguage = lang;
  localStorage.setItem('ai_scanner_lang', lang);
  applyTranslations();
  updateLanguageButtonUI();
}

// Export functions for use in other scripts
window.initI18n = initI18n;
window.toggleLanguage = toggleLanguage;
window.applyTranslations = applyTranslations;
window.setLanguage = setLanguage;
window.t = t;
window.currentAppLang = currentLanguage;
