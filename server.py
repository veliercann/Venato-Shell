# server.py (Windows için uyarlanmış B cihazında çalışacak)
import socket
import ssl
import subprocess
import json
import platform
import os
import threading
import time
import uuid
import tempfile
import random
import string

class RemoteServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.connections = {}
        self.device_info = {
            "hostname": platform.node(),
            "system": platform.system(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "uuid": str(uuid.uuid4())
        }
        
    def start_server(self):
        # SSL bağlantı için sertifika oluşturma
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        except:
            print("Sertifikalar bulunamadı, yeni sertifikalar oluşturuluyor...")
            self._generate_certificates()
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        
        # Server soketi oluştur
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Windows'ta SO_REUSEADDR farklı çalışabilir
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            print("SO_REUSEADDR ayarlanamadı, devam ediliyor...")
            
        # Bağlantı noktasını oluştur
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"Server {self.host}:{self.port} adresinde çalışıyor...")
            print(f"Windows sistemi üzerinde çalışıyor: {platform.system()} {platform.version()}")
            
            # Yerel IP adresini al ve göster
            hostname = socket.gethostname()
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            print(f"Bu cihazın IP adresleri: {', '.join(ip_addresses)}")
            
            while True:
                conn, addr = self.socket.accept()
                ssl_conn = context.wrap_socket(conn, server_side=True)
                
                # Yeni bağlantı için thread başlat
                client_thread = threading.Thread(target=self._handle_client, args=(ssl_conn, addr))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("Server kapatılıyor...")
        except Exception as e:
            print(f"Server hata: {str(e)}")
        finally:
            if self.socket:
                self.socket.close()
                
    def _generate_certificates(self):
        """Windows için OpenSSL bulunmayabileceğinden, alternatif sertifika oluşturma"""
        try:
            # Önce openssl ile deneyelim
            from subprocess import Popen, PIPE
            Popen([
                'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-days', '365', '-nodes', '-x509',
                '-subj', '/CN=localhost', '-keyout', 'server.key', '-out', 'server.crt'
            ]).wait()
        except:
            # OpenSSL bulunamadıysa Python ile oluştur
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                import datetime
                
                # Anahtar oluştur
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                
                # Sertifika bilgilerini ayarla
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                ])
                
                # Sertifika oluştur
                cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow()
                ).not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                ).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                    critical=False,
                ).sign(key, hashes.SHA256())
                
                # Private key dosyası
                with open("server.key", "wb") as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                # Sertifika dosyası
                with open("server.crt", "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                    
                print("Python cryptography kütüphanesi ile sertifikalar oluşturuldu.")
            except:
                print("Sertifika oluşturulamadı. OpenSSL veya cryptography kütüphanesi gerekli.")
                print("Lütfen 'pip install cryptography' komutunu çalıştırın.")
                exit(1)
                
    def _handle_client(self, client_socket, address):
        client_id = None
        try:
            # Client bilgilerini al
            client_info_data = client_socket.recv(4096)
            client_info = json.loads(client_info_data.decode('utf-8'))
            print(f"Yeni bağlantı isteği: {client_info['hostname']} ({address[0]})")
            
            # Kendi cihaz bilgilerini gönder
            client_socket.send(json.dumps(self.device_info).encode('utf-8'))
            
            # Bağlantı onay sorusu göster
            print("\nBağlantı isteği:")
            print(f"  Hostname: {client_info['hostname']}")
            print(f"  System: {client_info['system']} {client_info['version']}")
            print(f"  Machine: {client_info['machine']}")
            print(f"  Client ID: {client_info['uuid']}")
            
            response = input("\nBağlantıyı kabul ediyor musunuz? (E/H): ").strip().upper()
            
            if response != 'E':
                print("Bağlantı reddedildi.")
                client_socket.send(json.dumps({"status": "rejected"}).encode('utf-8'))
                client_socket.close()
                return
                
            # Bağlantıyı kabul et
            client_socket.send(json.dumps({"status": "accepted"}).encode('utf-8'))
            
            # Client ID'sini kaydet
            client_id = client_info["uuid"]
            self.connections[client_id] = {
                "socket": client_socket,
                "info": client_info,
                "address": address,
                "last_active": time.time()
            }
            
            print(f"Bağlantı kabul edildi. {client_info['hostname']} ile bağlantı kuruldu.")
            
            # Komut çalıştırma döngüsü
            while True:
                try:
                    # Komut al
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    command_data = json.loads(data.decode('utf-8'))
                    command = command_data.get("command", "")
                    
                    if command == "exit":
                        print(f"{client_info['hostname']} bağlantıyı sonlandırdı.")
                        break
                    
                    # Windows için komut işleme
                    if command.lower().startswith("cd "):
                        # CD komutu için özel işlem - Windows'ta Popen ile çalışmaz
                        new_dir = command[3:].strip()
                        try:
                            os.chdir(new_dir)
                            response = {
                                "status": "success",
                                "output": f"Dizin değiştirildi: {os.getcwd()}"
                            }
                        except Exception as e:
                            response = {
                                "status": "error",
                                "output": f"Hata: {str(e)}"
                            }
                    elif self._is_dangerous_command(command):
                        # Tehlikeli komutları engelle
                        response = {
                            "status": "error",
                            "output": "Güvenlik nedeniyle bu komut çalıştırılamaz."
                        }
                    else:
                        # Komutu çalıştır - Windows'ta komutlar farklı çalışır
                        print(f"Çalıştırılan komut: {command}")
                        try:
                            # Windows'ta komut işleme
                            # shell=True kullanımı Windows'ta bazı komutlar için gerekebilir
                            shell_needed = any(cmd in command.lower() for cmd in ["dir", "echo", "type", "copy", "move"])
                            
                            if shell_needed:
                                # Windows komutları için shell=True
                                process = subprocess.Popen(
                                    command,
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    shell=True,
                                    cwd=os.getcwd()
                                )
                            else:
                                # Diğer komutlar için normal çalıştırma
                                process = subprocess.Popen(
                                    command.split(), 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE,
                                    shell=False,
                                    cwd=os.getcwd()
                                )
                                
                            stdout, stderr = process.communicate(timeout=10)
                            
                            if stderr:
                                response = {
                                    "status": "error",
                                    "output": stderr.decode('utf-8', errors='replace')
                                }
                            else:
                                response = {
                                    "status": "success",
                                    "output": stdout.decode('utf-8', errors='replace')
                                }
                        except subprocess.TimeoutExpired:
                            process.kill()
                            response = {
                                "status": "timeout",
                                "output": "Komut zaman aşımına uğradı."
                            }
                        except Exception as e:
                            response = {
                                "status": "error",
                                "output": f"Hata: {str(e)}"
                            }
                    
                    # Yanıtı gönder
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    print("Geçersiz JSON formatı alındı.")
                    break
                except Exception as e:
                    print(f"Hata: {str(e)}")
                    break
                    
        except Exception as e:
            print(f"Bağlantı işleme hatası: {str(e)}")
        finally:
            client_socket.close()
            if client_id in self.connections:
                del self.connections[client_id]
    
    def _is_dangerous_command(self, command):
        """Windows için tehlikeli komutları kontrol et"""
        dangerous_commands = [
    # Kritik dosya/klasör silme
        "del /f", "del /s", "del /q", "rmdir /s", "rd /s", "deltree", "format",

    # Kayıt defteri ve sistem değişiklikleri
        "reg delete", "reg add", "reg update", "reg import",

    # Sistem kapatma/restart
        "shutdown", "restart", "logoff",

    # Görev ve servisleri öldürme
        "taskkill", "sc delete", "sc stop",

    # Ağ ayarlarını değiştiren
        "netsh",

    # Yetki ve sahiplik değiştirme
        "takeown", "icacls", "cacls",

    # PowerShell üzerinden tehlikeli komutlar
        "powershell", "Invoke-WebRequest", "Invoke-Expression", "iex",

    # Disk işlemleri
        "diskpart", "bcdedit",

    # Script veya komut kabuğu çalıştırma
        "wmic", "mshta", "cscript", "wscript",

    # Önemli uyarı: 'del' (parametresiz) bıraktım çünkü bazen günlük dosya temizliği için lazım olabilir.
    # 'move', 'copy', 'rename' gibi temel dosya işlemleri engellenmiyor.

]

        
        cmd_lower = command.lower()
        return any(cmd in cmd_lower for cmd in dangerous_commands)

if __name__ == "__main__":
    print("\nWindows Uzaktan Kontrol Sunucusu - Sürüm 1.0")
    print("---------------------------------------------")
    
    # Kolay çıkış için bilgi
    print("\nSunucuyu durdurmak için Ctrl+C tuşlarına basın\n")
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

    try:
        # SSL için gerekli kütüphaneleri kontrol et
        import ssl
    except ImportError:
        print("SSL kütüphanesi bulunamadı!")
        exit(1)
    
    server = RemoteServer()
    server.start_server()