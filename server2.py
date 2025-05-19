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
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import sys

# GUI renkleri
DARK_BG = "#2b2b2b"
LIGHT_TEXT = "#e0e0e0"
ACCENT_COLOR = "#007acc"
SUCCESS_COLOR = "#4caf50"
ERROR_COLOR = "#f44336"
WARNING_COLOR = "#ff9800"
HEADER_COLOR = "#3a3a3a"

class RemoteServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Venato Shell - Güvenli Uzaktan Bağlantı Sistemi")
        self.root.geometry("900x700")
        self.root.configure(bg=DARK_BG)
        
        # İkon ayarla (varsayılan bir ikon kullanılabilir ya da kendi ikonunuzu ekleyebilirsiniz)
        try:
            self.root.iconbitmap("logocuk.ico")
        except:
            pass
            
        # Pencere kapatıldığında güvenli çıkış
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Ana server thread'i
        self.server_thread = None
        self.server = None
        self.running = False
        
        # GUI stilini ayarla
        self.style = ttk.Style()
        self.style.theme_use('clam')  # En iyi özelleştirme seçenekleri için

        # Özel stil tanımlamaları
        self.style.configure("TFrame", background=DARK_BG)
        self.style.configure("TButton", 
                            background=ACCENT_COLOR, 
                            foreground=LIGHT_TEXT, 
                            padding=10, 
                            font=("Segoe UI", 10, "bold"),
                            borderwidth=0)
        self.style.map("TButton", 
                    background=[("active", "#005ca3"), ("pressed", "#004c86")])
        
        self.style.configure("Success.TButton", 
                          background=SUCCESS_COLOR, 
                          foreground=LIGHT_TEXT)
        self.style.map("Success.TButton", 
                    background=[("active", "#3d8b40"), ("pressed", "#2d6a30")])
        
        self.style.configure("Danger.TButton", 
                          background=ERROR_COLOR, 
                          foreground=LIGHT_TEXT)
        self.style.map("Danger.TButton",
                    background=[("active", "#d32f2f"), ("pressed", "#b71c1c")])
        
        self.style.configure("TLabel", 
                          background=DARK_BG, 
                          foreground=LIGHT_TEXT, 
                          font=("Segoe UI", 10))
        
        self.style.configure("Header.TLabel", 
                          background=HEADER_COLOR, 
                          foreground=LIGHT_TEXT, 
                          font=("Segoe UI", 12, "bold"),
                          padding=10)
        
        self.style.configure("Status.TLabel", 
                          font=("Segoe UI", 10, "bold"))
        
        # GUI bileşenlerini oluştur
        self.create_widgets()
        
        # Logo göster
        self.display_logo()
    
    def create_widgets(self):
        # Ana çerçeve
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Üst panel - Logo ve durum
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Logo alanı (daha sonra doldurulacak)
        self.logo_frame = ttk.Frame(top_frame, height=120)
        self.logo_frame.pack(fill=tk.X)
        
        # Durum çubuğu
        status_frame = ttk.Frame(top_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(status_frame, text="Durum:").pack(side=tk.LEFT, padx=(0, 5))
        self.status_label = ttk.Label(status_frame, text="Devre Dışı", foreground=ERROR_COLOR, style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT)
        
        # IP Adresi
        self.ip_var = tk.StringVar(value="Henüz başlatılmadı")
        ttk.Label(status_frame, text="IP:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Label(status_frame, textvariable=self.ip_var).pack(side=tk.LEFT)
        
        # Port
        self.port_var = tk.StringVar(value="5555")
        ttk.Label(status_frame, text="Port:").pack(side=tk.LEFT, padx=(20, 5))
        ttk.Entry(status_frame, textvariable=self.port_var, width=6).pack(side=tk.LEFT)
        
        # Orta bölüm
        middle_frame = ttk.Frame(main_frame)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Log alanı
        log_frame = ttk.LabelFrame(middle_frame, text="Sunucu Logları")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="#1e1e1e", fg=LIGHT_TEXT)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_area.configure(font=("Consolas", 10))
        self.log_area.bind("<Key>", lambda e: "break")  # Salt okunur
        
        # Alt panel - Bağlantılar ve Kontroller
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=10)
        
        # Kontrol düğmeleri
        control_frame = ttk.Frame(bottom_frame)
        control_frame.pack(fill=tk.X)
        
        self.start_button = ttk.Button(control_frame, text="Sunucuyu Başlat", 
                                     style="Success.TButton", command=self.start_server)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Sunucuyu Durdur", 
                                    style="Danger.TButton", command=self.stop_server)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.config(state=tk.DISABLED)
        
        # Bağlantılar sekmesi
        connections_frame = ttk.LabelFrame(main_frame, text="Aktif Bağlantılar")
        connections_frame.pack(fill=tk.BOTH, pady=10)
        
        # Bağlantılar listesi
        columns = ("id", "hostname", "ip", "system", "connected_time")
        self.connections_table = ttk.Treeview(connections_frame, columns=columns, show="headings", height=5)
        
        # Sütun başlıkları
        self.connections_table.heading("id", text="ID")
        self.connections_table.heading("hostname", text="Host Adı")
        self.connections_table.heading("ip", text="IP Adresi")
        self.connections_table.heading("system", text="Sistem")
        self.connections_table.heading("connected_time", text="Bağlantı Zamanı")
        
        # Sütun genişlikleri
        self.connections_table.column("id", width=60)
        self.connections_table.column("hostname", width=150)
        self.connections_table.column("ip", width=120)
        self.connections_table.column("system", width=150)
        self.connections_table.column("connected_time", width=150)
        
        self.connections_table.pack(fill=tk.BOTH, expand=True)
        
        # Alt bilgi çubuğu
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(footer_frame, text="Venato Shell v1.0 | © 2025").pack(side=tk.LEFT)
        ttk.Label(footer_frame, text="Veli'nin Güvenli Uzaktan Bağlantı Sistemi").pack(side=tk.RIGHT)
        
    def display_logo(self):
        # ASCII logoyu görüntüle (renkli olmayan versiyonu)
        logo_text = tk.Text(self.logo_frame, height=6, bd=0, bg=DARK_BG, fg=ACCENT_COLOR)
        logo_text.pack(fill=tk.BOTH)
        
        logo = '''
 __     __                _           _____ _          _ _ 
 \ \   / /__ _ __   __ _| |_ ___    |  ___| |__   ___| | |
  \ \ / / _ \ '_ \ / _` | __/ _ \   | |_  | '_ \ / _ \ | |
   \ V /  __/ | | | (_| | || (_) |  |  _| | | | |  __/ | |
    \_/ \___|_| |_|\__,_|\__\___/   |_|   |_| |_|\___|_|_|
        '''
        
        logo_text.insert(tk.END, logo)
        logo_text.tag_configure("center", justify="center")
        logo_text.tag_add("center", "1.0", "end")
        
        # Farklı renkler ekle
        logo_text.tag_configure("accent", foreground=ACCENT_COLOR)
        logo_text.tag_add("accent", "1.0", "6.0")
        
        # Alt metin
        logo_text.insert(tk.END, "\n      Veli'nin Güvenli Uzaktan Bağlantı Sistemi")
        logo_text.tag_configure("subtitle", foreground=WARNING_COLOR, font=("Segoe UI", 10, "bold"))
        logo_text.tag_add("subtitle", "7.0", "end")
        
        logo_text.configure(state="disabled")  # Salt okunur yap
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Log seviyesine göre renklendirme yap
        tag = None
        if level == "INFO":
            tag = "info"
            level_str = "[INFO]"
        elif level == "SUCCESS":
            tag = "success"
            level_str = "[OK]"
        elif level == "ERROR":
            tag = "error"
            level_str = "[HATA]"
        elif level == "WARNING":
            tag = "warning"
            level_str = "[UYARI]"
        elif level == "SYSTEM":
            tag = "system"
            level_str = "[SİSTEM]"
        
        log_entry = f"{timestamp} {level_str} {message}\n"
        
        # Ana thread'den çağrılıp çağrılmadığını kontrol et
        if threading.current_thread() is threading.main_thread():
            self._insert_log(log_entry, tag)
        else:
            # Diğer thread'lerden GUI güncellemesi yap
            self.root.after(0, lambda: self._insert_log(log_entry, tag))
    
    def _insert_log(self, log_entry, tag):
        self.log_area.insert(tk.END, log_entry)
        
        # Renklendirme
        if tag == "info":
            self.log_area.tag_configure("info", foreground=LIGHT_TEXT)
            self.log_area.tag_add("info", f"end-{len(log_entry) + 1}c", "end-1c")
        elif tag == "success":
            self.log_area.tag_configure("success", foreground=SUCCESS_COLOR)
            self.log_area.tag_add("success", f"end-{len(log_entry) + 1}c", "end-1c")
        elif tag == "error":
            self.log_area.tag_configure("error", foreground=ERROR_COLOR)
            self.log_area.tag_add("error", f"end-{len(log_entry) + 1}c", "end-1c")
        elif tag == "warning":
            self.log_area.tag_configure("warning", foreground=WARNING_COLOR)
            self.log_area.tag_add("warning", f"end-{len(log_entry) + 1}c", "end-1c")
        elif tag == "system":
            self.log_area.tag_configure("system", foreground="#9e9e9e")
            self.log_area.tag_add("system", f"end-{len(log_entry) + 1}c", "end-1c")
        
        # Otomatik kaydır
        self.log_area.see(tk.END)
    
    def update_connection_table(self, connections):
        # Önce tabloyu temizle
        for item in self.connections_table.get_children():
            self.connections_table.delete(item)
        
        # Yeni bağlantıları ekle
        for client_id, conn_data in connections.items():
            # Kısaltılmış ID
            short_id = client_id[:8] + "..."
            
            # Bağlantı zamanı
            connected_time = datetime.fromtimestamp(conn_data["last_active"]).strftime("%H:%M:%S %d/%m/%Y")
            
            # Sistem bilgisi
            system_info = f"{conn_data['info']['system']} {conn_data['info']['machine']}"
            
            # Tabloya ekle
            self.connections_table.insert("", tk.END, values=(
                short_id,
                conn_data["info"]["hostname"],
                conn_data["address"][0],
                system_info,
                connected_time
            ))
    
    def start_server(self):
        try:
            port = int(self.port_var.get())
            if port < 1 or port > 65535:
                raise ValueError("Port numarası 1-65535 arasında olmalıdır.")
        except ValueError as e:
            messagebox.showerror("Hata", f"Geçersiz port numarası: {str(e)}")
            return
        
        self.log("Sunucu başlatılıyor...", "SYSTEM")
        
        # RemoteServer sınıfını örneklendir
        self.server = RemoteServer(port=port, gui=self)
        
        # Server'ı ayrı bir thread'de başlat
        self.server_thread = threading.Thread(target=self.server.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Düğme durumlarını güncelle
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Durum etiketini güncelle
        self.status_label.config(text="Aktif", foreground=SUCCESS_COLOR)
        
        self.running = True
    
    def stop_server(self):
        if messagebox.askyesno("Sunucuyu Durdur", "Sunucuyu durdurmak istediğinizden emin misiniz?"):
            if self.server:
                self.log("Sunucu durduruluyor...", "SYSTEM")
                
                # Tüm bağlantıları temizle ve soketi kapat
                for client_id in list(self.server.connections.keys()):
                    try:
                        self.server.connections[client_id]["socket"].close()
                    except:
                        pass
                
                try:
                    if self.server.socket:
                        self.server.socket.close()
                except:
                    pass
                
                # Durum etiketini güncelle
                self.status_label.config(text="Devre Dışı", foreground=ERROR_COLOR)
                
                # Düğme durumlarını güncelle
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                
                # Bağlantı tablosunu temizle
                for item in self.connections_table.get_children():
                    self.connections_table.delete(item)
                
                self.log("Sunucu durduruldu.", "WARNING")
                self.running = False
    
    def on_closing(self):
        if self.running:
            if messagebox.askyesno("Çıkış", "Sunucu hala çalışıyor. Çıkmak istediğinden emin misin?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

    def show_connection_dialog(self, client_info, address):
        """Bağlantı onay dialogunu göster ve kullanıcının cevabını döndür"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Yeni Bağlantı İsteği")
        dialog.geometry("400x250")
        dialog.configure(bg=DARK_BG)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Dialog içeriği
        frame = ttk.Frame(dialog)
        frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Yeni Bağlantı İsteği", font=("Segoe UI", 12, "bold")).pack(pady=(0, 10))
        
        info_frame = ttk.Frame(frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        # Bilgileri göster
        ttk.Label(info_frame, text=f"Hostname: {client_info['hostname']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"IP Adresi: {address[0]}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Sistem: {client_info['system']} {client_info['version']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Machine: {client_info['machine']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Client ID: {client_info['uuid']}").pack(anchor=tk.W)
        
        # Butonlar
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=3, fill=tk.X)
        
        result = [False]  # Liste kullanarak değeri referans yoluyla aktarıyoruz
        
        def on_accept():
            result[0] = True
            dialog.destroy()
            
        def on_reject():
            result[0] = False
            dialog.destroy()
        
        ttk.Button(button_frame, text="Kabul Et", style="Success.TButton", command=on_accept).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Reddet", style="Danger.TButton", command=on_reject).pack(side=tk.LEFT, padx=10)
        
        # Dialog kapanana kadar bekle
        self.root.wait_window(dialog)
        return result[0]

class RemoteServer:
    def __init__(self, host='0.0.0.0', port=5555, gui=None):
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
        self.gui = gui  # GUI referansı
        
    def start_server(self):
        # SSL bağlantı için sertifika oluşturma
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        except:
            if self.gui:
                self.gui.log("Sertifikalar bulunamadı, yeni sertifikalar oluşturuluyor...", "WARNING")
            else:
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
            if self.gui:
                self.gui.log("SO_REUSEADDR ayarlanamadı, devam ediliyor...", "WARNING")
            else:
                print("SO_REUSEADDR ayarlanamadı, devam ediliyor...")
            
        # Bağlantı noktasını oluştur
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            if self.gui:
                self.gui.log(f"Server {self.host}:{self.port} adresinde çalışıyor...", "SUCCESS")
                self.gui.log(f"Windows sistemi üzerinde çalışıyor: {platform.system()} {platform.version()}", "INFO")
            else:
                print(f"Server {self.host}:{self.port} adresinde çalışıyor...")
                print(f"Windows sistemi üzerinde çalışıyor: {platform.system()} {platform.version()}")
            
            # Yerel IP adresini al ve göster
            hostname = socket.gethostname()
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            
            if self.gui:
                self.gui.log(f"Bu cihazın IP adresleri: {', '.join(ip_addresses)}", "INFO")
                # GUI'deki IP adresini güncelle
                if ip_addresses:
                    # Filtre IPv4 adreslerini al (genellikle 192.168.x.x şeklinde)
                    local_ips = [ip for ip in ip_addresses if ip.startswith("192.168.") or ip.startswith("10.")]
                    if local_ips:
                        self.gui.ip_var.set(local_ips[0])
                    else:
                        self.gui.ip_var.set(ip_addresses[0])
            else:
                print(f"Bu cihazın IP adresleri: {', '.join(ip_addresses)}")
            
            # Bağlantı dinleme döngüsü
            while True:
                conn, addr = self.socket.accept()
                ssl_conn = context.wrap_socket(conn, server_side=True)
                
                # Yeni bağlantı için thread başlat
                client_thread = threading.Thread(target=self._handle_client, args=(ssl_conn, addr))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            if self.gui:
                self.gui.log("Server kapatılıyor...", "WARNING")
            else:
                print("Server kapatılıyor...")
        except Exception as e:
            error_msg = f"Server hata: {str(e)}"
            if self.gui:
                self.gui.log(error_msg, "ERROR")
            else:
                print(error_msg)
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
            if self.gui:
                self.gui.log("OpenSSL ile sertifikalar oluşturuldu.", "SUCCESS")
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
                
                if self.gui:
                    self.gui.log("Python cryptography kütüphanesi ile sertifikalar oluşturuldu.", "SUCCESS")
                else:
                    print("Python cryptography kütüphanesi ile sertifikalar oluşturuldu.")
            except Exception as e:
                error_msg = f"Sertifika oluşturulamadı: {str(e)}"
                if self.gui:
                    self.gui.log(error_msg, "ERROR")
                    self.gui.log("Lütfen 'pip install cryptography' komutunu çalıştırın.", "WARNING")
                else:
                    print("Sertifika oluşturulamadı. OpenSSL veya cryptography kütüphanesi gerekli.")
                    print("Lütfen 'pip install cryptography' komutunu çalıştırın.")
                exit(1)
                
    def _handle_client(self, client_socket, address):
        client_id = None
        try:
            # Client bilgilerini al
            client_info_data = client_socket.recv(4096)
            client_info = json.loads(client_info_data.decode('utf-8'))
            
            connection_msg = f"Yeni bağlantı isteği: {client_info['hostname']} ({address[0]})"
            if self.gui:
                self.gui.log(connection_msg, "INFO")
            else:
                print(connection_msg)
            
            # Kendi cihaz bilgilerini gönder
            client_socket.send(json.dumps(self.device_info).encode('utf-8'))
            
            # Bağlantı onay sorusu göster
            connection_details = f"\nBağlantı isteği:\n"
            connection_details += f"  Hostname: {client_info['hostname']}\n"
            connection_details += f"  System: {client_info['system']} {client_info['version']}\n"
            connection_details += f"  Machine: {client_info['machine']}\n"
            connection_details += f"  Client ID: {client_info['uuid']}"
            connection_details += f"  IP Adresi: {address[0]}"
            connection_details += f"  Port: {address[1]}"
            connection_details += f"  Bağlantı Zamanı: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
            connection_details += f"  Cihaz Bilgisi: {client_info['system']} {client_info['version']}"
            connection_details += f"  Makine Bilgisi: {client_info['machine']}"
            
            
            if self.gui:
                self.gui.log(connection_details, "INFO")
                # GUI dialog ile sor
                accepted = self.gui.show_connection_dialog(client_info, address)
            else:
                print(connection_details)
                response = input("\nBağlantıyı kabul ediyor musunuz? (E/H): ").strip().upper()
                accepted = (response == 'E')
            
            if not accepted:
                reject_msg = "Bağlantı reddedildi."
                if self.gui:
                    self.gui.log(reject_msg, "WARNING")
                else:
                    print(reject_msg)
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
            
            accept_msg = f"Bağlantı kabul edildi. {client_info['hostname']} ile bağlantı kuruldu."
            if self.gui:
                self.gui.log(accept_msg, "SUCCESS")
                # GUI'deki bağlantı tablosunu güncelle
                self.gui.update_connection_table(self.connections)
            else:
                print(accept_msg)
            
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
                        exit_msg = f"{client_info['hostname']} bağlantıyı sonlandırdı."
                        if self.gui:
                            self.gui.log(exit_msg, "WARNING")
                        else:
                            print(exit_msg)
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
                        command_msg = f"Çalıştırılan komut: {command}"
                        if self.gui:
                            self.gui.log(command_msg, "INFO")
                        else:
                            print(command_msg)
                            
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
                    error_msg = "Geçersiz JSON formatı alındı."
                    if self.gui:
                        self.gui.log(error_msg, "ERROR")
                    else:
                        print(error_msg)
                    break
                    
                except Exception as e:
                    error_msg = f"Hata: {str(e)}"
                    if self.gui:
                        self.gui.log(error_msg, "ERROR")
                    else:
                        print(error_msg)
                    break
                    
        except Exception as e:
            error_msg = f"Bağlantı işleme hatası: {str(e)}"
            if self.gui:
                self.gui.log(error_msg, "ERROR")
            else:
                print(error_msg)
        finally:
            client_socket.close()
            if client_id in self.connections:
                del self.connections[client_id]
                # GUI'deki bağlantı tablosunu güncelle
                if self.gui:
                    self.gui.root.after(0, lambda: self.gui.update_connection_table(self.connections))
    
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

def main():
    try:
        # Gerekli kütüphaneleri kontrol et
        required_modules = ['ssl', 'tkinter', 'threading', 'socket', 'json']
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            print("Aşağıdaki gerekli modüller bulunamadı:")
            for module in missing_modules:
                print(f"  - {module}")
            print("\nLütfen şu komutu çalıştırarak gerekli modülleri yükleyin:")
            print("pip install " + " ".join(missing_modules))
            return
        
        # GUI başlat
        root = tk.Tk()
        app = RemoteServerGUI(root)
        root.mainloop()
        
    except Exception as e:
        print(f"Başlatma hatası: {str(e)}")

if __name__ == "__main__":
    main()