# 🌐 Hướng Dẫn Áp Dụng Đa Ngôn Ngữ Cho AI Security Scanner

## Tóm Tắt
Hệ thống đa ngôn ngữ đã được triển khai hoàn chỉnh với:
- ✅ File [`i18n.js`](static/i18n.js) chứa translation dictionary (VI/EN)
- ✅ Function `toggleLanguage()` đã được implement
- ✅ Auto-save preference vào localStorage
- ✅ Script đã được thêm vào HTML head

## Cách Sử Dụng

### 1. Để Thêm Dịch Cho Text Mới
Thêm attribute `data-i18n="key"` vào element HTML:

```html
<!-- VÍ DỤ -->
<span data-i18n="btn_save">Lưu cấu hình</span>
```

### 2. Dictionary Keys Đã Có Sẵn
File `i18n.js` đã có **180+ translation keys** bao gồm:

#### Navigation
- `nav_scan`, `nav_findings`, `nav_dashboard`, `nav_remediation`, etc.

#### Buttons
- `btn_start_scan`, `btn_save_config`, `btn_refresh`, `btn_export`, etc.

#### Labels
- `label_target_url`, `label_target_model`, `label_timeout`, etc.

#### Status
- `status_connected`, `status_loading`, `status_ready`, etc.

#### Messages
- `toast_success`, `toast_error`, `toast_connection_failed`, etc.

### 3. Các Element Đã Được Đánh Dấu
File HTML hiện tại ĐÃ CÓ một số `data-i18n` attributes:
- Navigation menu items (lines 47-114)
- Topbar buttons (lines 144-190)

### 4. Cần Thêm `data-i18n` Cho:

#### A. Banner Text (Lines 210-224)
```html
<h1 class="banner-main-title" data-i18n="banner_title">AI Security Scanner</h1>
<p class="banner-main-sub" data-i18n="banner_subtitle">Đánh giá và phát hiện...</p>
<span class="tagline-1" data-i18n="banner_tagline1">Safer AI</span>
<span class="tagline-2" data-i18n="banner_tagline2">Stronger Tomorrow</span>
```

#### B. Card Titles
```html
<div class="card-title" data-i18n="card_config_title">Cấu hình quét hệ thống</div>
<div class="card-subtitle" data-i18n="card_config_subtitle">Cung cấp thông tin...</div>
```

#### C. Form Labels
```html
<label class="form-label" data-i18n="label_target_url">Target URL</label>
<label class="form-label" data-i18n="label_timeout">Timeout (sec)</label>
```

#### D. Buttons
```html
<button onclick="..." data-i18n="btn_start_scan">Bắt đầu quét</button>
<button onclick="..." data-i18n="btn_save_config">Lưu cấu hình</button>
```

#### E. Table Headers
```html
<th data-i18n="th_module">Module</th>
<th data-i18n="th_severity">Severity</th>
<th data-i18n="th_risk_score">Risk Score</th>
```

## Quy Tắc Quan Trọng

### ✅ NÊN Dịch:
- Tiêu đề, mô tả, hướng dẫn
- Nhãn form, nút bấm
- Thông báo, trạng thái
- Text giao diện người dùng

### ❌ KHÔNG Dịch:
- Tên module attack: `Prompt Injection`, `Jailbreak`, `RAG Security`
- Code OWASP: `LLM01`, `LLM02`
- Code MITRE: `AML.T0051`
- Payload content
- AI responses
- Technical terms: `CVSS`, `SSE`, `API`, `JSON`

## Ví Dụ Hoàn Chỉnh

### Trước Khi Thêm:
```html
<div class="card-title">Cấu hình quét hệ thống</div>
<button onclick="startScan()">Bắt đầu quét</button>
```

### Sau Khi Thêm:
```html
<div class="card-title" data-i18n="card_config_title">Cấu hình quét hệ thống</div>
<button onclick="startScan()" data-i18n="btn_start_scan">Bắt đầu quét</button>
```

### Kết Quả:
- **Tiếng Việt**: "Cấu hình quét hệ thống" / "Bắt đầu quét"
- **English**: "System Scan Configuration" / "Start Scan"

## Testing

1. Mở trình duyệt và load trang
2. Nhấn nút Language Toggle (🇻🇳/🇺🇸) trên topbar
3. Kiểm tra tất cả text có `data-i18n` đã chuyển đổi ngôn ngữ
4. Refresh trang - ngôn ngữ được lưu vào localStorage

## Auto-Apply Script

Để tự động thêm `data-i18n` cho các element phổ biến, chạy:

```javascript
// Run in browser console
document.querySelectorAll('.card-title').forEach(el => {
  if (!el.hasAttribute('data-i18n')) {
    console.log('Missing data-i18n:', el.textContent.trim());
  }
});
```

## Thêm Translation Key Mới

Nếu cần thêm key mới vào dictionary:

1. Mở [`web/static/i18n.js`](static/i18n.js)
2. Thêm vào cả 2 ngôn ngữ (vi và en):

```javascript
vi: {
  my_new_key: "Text tiếng Việt",
  // ...
},
en: {
  my_new_key: "English text",
  // ...
}
```

3. Sử dụng trong HTML:
```html
<span data-i18n="my_new_key">Text tiếng Việt</span>
```

## Status Hiện Tại

✅ **Hoàn Thành**:
- Translation dictionary (180+ keys)
- Toggle function với localStorage
- Script integration
- DOMContentLoaded initialization

⏳ **Cần Làm**:
- Thêm `data-i18n` attributes cho ~200 text elements trong HTML
- Test toàn bộ giao diện
- Fix edge cases (nếu có)

## Liên Hệ
Mọi thắc mắc về hệ thống i18n vui lòng tham khảo file `i18n.js`.
