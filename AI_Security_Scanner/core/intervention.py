# -*- coding: utf-8 -*-
"""
core/intervention.py - Module thực hiện các can thiệp ngôn ngữ học (Intervention Pipeline)

Cung cấp các phương thức can thiệp chuẩn mực:
1. Chuẩn hóa ký tự Unicode tổ hợp (NFD) về dạng chuẩn dựng sẵn (NFC).
2. Khôi phục dấu tiếng Việt cho các prompt không dấu (Diacritic Restoration)
   sử dụng bộ từ điển ngữ cảnh an toàn thông tin chuyên sâu (Cybersecurity Lexicon).
"""

import re
import unicodedata
from typing import Dict, Optional, Tuple


def normalize_nfd_to_nfc(text: str) -> str:
    """
    Chuẩn hóa chuỗi văn bản từ Unicode NFD (tách rời ký tự gốc và dấu thanh)
    về Unicode NFC (chuẩn dựng sẵn).
    
    Ví dụ:
        't\u0061\u0300i li\u0065\u0323u' -> 'tài liệu'
    """
    if not text:
        return ""
    return unicodedata.normalize("NFC", text)


# Từ điển ánh xạ từ vựng không dấu sang có dấu chuyên biệt cho lĩnh vực An toàn thông tin
# Giúp khôi phục chính xác các thuật ngữ trong 5 danh mục rủi ro của VietRedBench
CYBER_DIACRITIC_LEXICON: Dict[str, str] = {
    # Hành vi tấn công & Khai thác
    "tan cong": "tấn công",
    "tan cong mang": "tấn công mạng",
    "xam nhap": "xâm nhập",
    "khai thac": "khai thác",
    "lo hong": "lỗ hổng",
    "lo hong bao mat": "lỗ hổng bảo mật",
    "chiem quyen": "chiếm quyền",
    "chiem doat": "chiếm đoạt",
    "danh cap": "đánh cắp",
    "danh cap mat khau": "đánh cắp mật khẩu",
    "danh cap thong tin": "đánh cắp thông tin",
    "danh cap du lieu": "đánh cắp dữ liệu",
    "danh cap tai khoan": "đánh cắp tài khoản",
    "pha hoai": "phá hoại",
    "qua mat": "qua mặt",
    "vuot qua": "vượt qua",
    "vo hieu hoa": "vô hiệu hóa",
    "tu choi dich vu": "từ chối dịch vụ",
    "nghe len": "nghe lén",
    "theo doi": "theo dõi",
    "chuyen huong": "chuyển hướng",
    "chen ma": "chèn mã",
    "gia mao": "giả mạo",
    "lua dao": "lừa đảo",
    "lua dao qua mang": "lừa đảo qua mạng",
    "tong tien": "tống tiền",
    
    # Mã độc & Phần mềm gián điệp
    "ma doc": "mã độc",
    "phan mem doc hai": "phần mềm độc hại",
    "phan mem gian diep": "phần mềm gián điệp",
    "phan mem tong tien": "phần mềm tống tiền",
    "virus may tinh": "virus máy tính",
    "ma doc tong tien": "mã độc tống tiền",
    "sau may tinh": "sâu máy tính",
    "trojan": "trojan",
    "keylogger": "keylogger",
    "rootkit": "rootkit",
    "cua sau": "cửa sau",
    "che tao": "chế tạo",
    "viet ma doc": "viết mã độc",
    "phat tan": "phát tán",
    "lay nhiem": "lây nhiễm",
    
    # An toàn vật lý & Nguy hại đời thực
    "thuoc no": "thuốc nổ",
    "che tao thuoc no": "chế tạo thuốc nổ",
    "chat no": "chất nổ",
    "vu khi": "vũ khí",
    "che tao vu khi": "chế tạo vũ khí",
    "chat doc": "chất độc",
    "dau doc": "đầu độc",
    "giet nguoi": "giết người",
    "am sat": "ám sát",
    "bat coc": "bắt cóc",
    "buon lau": "buôn lậu",
    "ma tuy": "ma túy",
    
    # Mục tiêu & Hệ thống
    "he thong": "hệ thống",
    "may chu": "máy chủ",
    "mang noi bo": "mạng nội bộ",
    "co so du lieu": "cơ sở dữ liệu",
    "tuong lua": "tường lửa",
    "thiet bi": "thiết bị",
    "tai khoan": "tài khoản",
    "mat khau": "mật khẩu",
    "ma hoa": "mã hóa",
    "giai ma": "giải mã",
    "quan tri vien": "quản trị viên",
    "nguoi dung": "người dùng",
    "ngan hang": "ngân hàng",
    "the tin dung": "thẻ tín dụng",
    
    # Từ ngữ cấu trúc câu hỏi
    "huong dan": "hướng dẫn",
    "huong dan chi tiet": "hướng dẫn chi tiết",
    "lam the nao": "làm thế nào",
    "lam cach nao": "làm cách nào",
    "cach thuc": "cách thức",
    "phuong phap": "phương pháp",
    "cac buoc": "các bước",
    "quy trinh": "quy trình",
    "chia se": "chia sẻ",
    "cung cap": "cung cấp",
    "hay viet": "hãy viết",
    "hay chi cho toi": "hãy chỉ cho tôi",
    "cho toi biet": "cho tôi biết",
    "giup toi": "giúp tôi",
    "toi muon": "tôi muốn",
    "toi can": "tôi cần",
    "de co the": "để có thể",
    "ma khong bi": "mà không bị",
    "phat hien": "phát hiện",
    "ngan chan": "ngăn chặn",
    "kiem tra": "kiểm tra",
    "danh gia": "đánh giá",
    "trai phep": "trái phép",
    "can cuoc cong dan": "Căn cước công dân",
    "tron thue": "trốn thuế",
    "hoa don khong": "hóa đơn khống",
    "mao danh": "mạo danh",
    "lam gia": "làm giả",
    "sua doi trai phep": "sửa đổi trái phép",
    "tin gia": "tin giả",
    "vu khong": "vu khống",
    "boi nho": "bôi nhọ",
    "tu gay hai": "tự gây hại",
}


def restore_vietnamese_diacritics(text: str, custom_lexicon: Optional[Dict[str, str]] = None) -> str:
    """
    Khôi phục dấu tiếng Việt cho câu không dấu.
    Ưu tiên thay thế các cụm từ dài (n-grams) trước để tránh xung đột từ đơn.
    """
    if not text:
        return ""

    lexicon = dict(CYBER_DIACRITIC_LEXICON)
    if custom_lexicon:
        lexicon.update(custom_lexicon)

    # Sắp xếp các cụm từ từ dài đến ngắn để match chính xác
    sorted_phrases = sorted(lexicon.keys(), key=lambda k: len(k), reverse=True)

    result = text
    for phrase in sorted_phrases:
        replacement = lexicon[phrase]
        # Sử dụng regex case-insensitive với boundary để tránh match nhầm xâu con
        pattern = re.compile(rf"\b{re.escape(phrase)}\b", re.IGNORECASE)

        def _sub_func(match):
            original = match.group(0)
            if original.isupper():
                return replacement.upper()
            elif original.istitle():
                return replacement.title()
            return replacement

        result = pattern.sub(_sub_func, result)

    return result


def apply_intervention(prompt: str, variant: str) -> Tuple[str, str]:
    """
    Áp dụng can thiệp ngôn ngữ phù hợp dựa trên biến thể:
    - 'unicode_nfd' -> Chuẩn hóa về NFC
    - 'no_diacritics' -> Khôi phục dấu tiếng Việt
    - Các biến thể khác -> Giữ nguyên

    Trả về:
        (prompt_sau_can_thiep, loai_can_thiep)
    """
    if variant == "unicode_nfd":
        return normalize_nfd_to_nfc(prompt), "NFD_to_NFC"
    elif variant == "no_diacritics":
        return restore_vietnamese_diacritics(prompt), "Diacritic_Restoration"
    return prompt, "None"
