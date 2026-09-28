import socket

class PortScanner:
    def __init__(self):
        self.name = "AI Service Port Scanner"
        self.description = "Quét các cổng mạng (ports) phổ biến của các dịch vụ AI/ML (Ollama, MLflow, Ray, v.v.)"
        
        # Các cổng phổ biến của AI theo MITRE ATLAS (Active Scanning)
        self.ai_ports = {
            11434: "Ollama (Local LLM)",
            5000: "MLflow / Flask API",
            8000: "FastAPI / vLLM",
            8265: "Ray Dashboard (Distributed ML)",
            6333: "Qdrant (Vector DB)",
            8080: "Generic HTTP (Thường dùng cho web UI AI)"
        }

    def run(self, host="127.0.0.1"):
        print(f"[*] Bắt đầu quét các dịch vụ AI trên {host}...")
        found_services = []
        
        for port, service_name in self.ai_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[+] ĐÃ TÌM THẤY DỊCH VỤ: Cổng {port} đang mở -> Có thể là {service_name}")
                found_services.append((port, service_name))
            sock.close()
            
        if not found_services:
            print("[-] Không tìm thấy dịch vụ AI nào đang mở.")
            
        return found_services