# client.py (A cihazında çalışacak)
import socket
import ssl
import json
import platform
import uuid


class RemoteClient:
    def __init__(self, server_host, server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.connected = False
        self.server_info = None
        self.device_info = {
            "hostname": platform.node(),
            "system": platform.system(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "uuid": str(uuid.uuid4())
        }
        
    def connect_to_server(self):
        try:
            # SSL bağlantısı için context oluştur
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Gerçek uygulamada sertifika doğrulaması yapılmalıdır
            
            # Socket oluştur ve sunucuya bağlan
            plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = context.wrap_socket(plain_socket, server_hostname=self.server_host)
            self.socket.connect((self.server_host, self.server_port))
            
            # Kendi cihaz bilgilerini gönder
            self.socket.send(json.dumps(self.device_info).encode('utf-8'))
            
            # Sunucu cihaz bilgilerini al
            server_info_data = self.socket.recv(4096)
            self.server_info = json.loads(server_info_data.decode('utf-8'))
            
            print("\nSunucu Bilgileri:")
            print(f"  Hostname: {self.server_info['hostname']}")
            print(f"  System: {self.server_info['system']} {self.server_info['version']}")
            print(f"  Machine: {self.server_info['machine']}")
            print(f"  Server ID: {self.server_info['uuid']}")
            
            # Bağlantı onayını bekle
            response_data = self.socket.recv(4096)
            response = json.loads(response_data.decode('utf-8'))
            
            if response.get("status") != "accepted":
                print("Bağlantı isteği reddedildi.")
                self.socket.close()
                return False
                
            print(f"\nBağlantı kuruldu: {self.server_info['hostname']}")
            self.connected = True
            return True
            
        except ConnectionRefusedError:
            print(f"Bağlantı reddedildi: {self.server_host}:{self.server_port}")
            return False
        except Exception as e:
            print(f"Bağlantı hatası: {str(e)}")
            return False
            
    def send_command(self, command):
        if not self.connected:
            print("Sunucuya bağlı değil!")
            return False
            
        try:
            # Komutu gönder
            command_data = {"command": command}
            self.socket.send(json.dumps(command_data).encode('utf-8'))
            
            # Yanıtı al
            response_data = self.socket.recv(4096)
            response = json.loads(response_data.decode('utf-8'))
            
            # Yanıtı göster
            if response["status"] == "success":
                print(response["output"])
            else:
                print(f"Hata: {response['output']}")
                
            return True
            
        except Exception as e:
            print(f"Komut gönderme hatası: {str(e)}")
            self.connected = False
            return False
            
    def start_shell(self):
        if not self.connect_to_server():
            return
            
        print("\nUzak sunucuda komut çalıştırmak için komutları yazın.")
        print("Çıkmak için 'exit' yazın.\n")
        
        while self.connected:
            command = input(f"{self.server_info['hostname']}> ").strip()
            
            if not command:
                continue
                
            if command.lower() == "exit":
                # Çıkış komutu gönder
                self.send_command("exit")
                self.connected = False
                self.socket.close()
                print("Bağlantı sonlandırıldı.")
                break
                
            self.send_command(command)

if __name__ == "__main__":
    print("\nWindows Uzaktan Kontrol İstemcisi - Sürüm 1.0")
    print("---------------------------------------------")
    
    # Kolay çıkış için bilgi
    
    print("Not: Bu sunucu sadece Windows sistemlerde çalışır.")


    from colorama import Fore, Style, init
    init(autoreset=True)

    logo = f"""
{Fore.CYAN}{Style.BRIGHT}
 __     __                _           _____ _          _ _ 
 \ \   / /__ _ __   __ _| |_ ___    |  ___| |__   ___| | |
  \ \ / / _ \ '_ \ / _` | __/ _ \   | |_  | '_ \ / _ \ | |
   \ V /  __/ | | | (_| | || (_) |  |  _| | | | |  __/ | |
    \_/ \___|_| |_|\__,_|\__\___/   |_|   |_| |_|\___|_|_|

       {Fore.YELLOW}Veli'nin Güvenli Uzaktan Bağlantı Sistemi
             {Fore.RED}Backdoor Server v1.0
"""

    print(logo)






    server_host = input("Bağlanılacak sunucu IP adresi: ")
    client = RemoteClient(server_host)
    client.start_shell()