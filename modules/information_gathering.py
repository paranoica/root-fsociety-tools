# region: outer menu operations
menu_name = "Information gathering"
menu_items = [
    "Network mapper",
    "Host2IP",
    "WPScan",
    "CMS-Map",
    "XSStrike",
    "Doork",
    "Crips"
]

menu_items.append("Back")
# endregion

# region: additonal imports
import os
import sys

import nmap # type: ignore
import socket

import shutil
import subprocess

from colorama import Fore
from datetime import datetime
import dns.resolver as _dns_resolver # type: ignore
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

# region: override class: network mapper
class Nmap:
    menu_items = [
        "Quick scan",
        "Full scan",
        "Custom scan",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Nmap: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nNmap options:")
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

        if sel == "Quick scan":
            self.quick_scan(ctx)
        elif sel == "Full scan":
            self.full_scan(ctx)
        elif sel == "Custom scan":
            self.custom_scan(ctx)

    def quick_scan(self, ctx):
        target = input("Enter target IP/host: ").strip()
        nm = nmap.PortScanner()
        
        safe_print(ctx, f"\n[*] Quick scanning {target} (top ports)...")
        nm.scan(hosts=target, arguments='-F')
        
        for host in nm.all_hosts():
            safe_print(ctx, f"[+] Host: {host} ({nm[host].hostname()})")

            for proto in nm[host].all_protocols():
                lports = sorted(nm[host][proto].keys())
                if not lports:
                    continue

                safe_print(ctx, f"  Protocol: {proto}")
                for port in lports:
                    port_info = nm[host][proto][port]
                    
                    state = port_info.get("state", "unknown")
                    name = port_info.get("name", "")

                    product = port_info.get("product", "")
                    version = port_info.get("version", "")

                    extr = f"{product} {version}".strip()
                    line = f"    - {port}/{proto} -> {state}"

                    if name:
                        line += f" ({name})"

                    if extr:
                        line += f" [{extr}]"

                    safe_print(ctx, line)

        safe_print(ctx, "[*] Scanning has been finished!")

    def full_scan(self, ctx):
        target = input("Enter target IP/host: ").strip()
        nm = nmap.PortScanner()

        safe_print(ctx, f"\n[*] Full scanning {target} (all ports)...")
        nm.scan(hosts=target, arguments='-p-')

        for host in nm.all_hosts():
            safe_print(ctx, f"[+] Host: {host} ({nm[host].hostname()})")

            for proto in nm[host].all_protocols():
                lports = sorted(nm[host][proto].keys())
                if not lports:
                    continue

                safe_print(ctx, f"  Protocol: {proto}")
                for port in lports:
                    port_info = nm[host][proto][port]
                    
                    state = port_info.get("state", "unknown")
                    name = port_info.get("name", "")

                    product = port_info.get("product", "")
                    version = port_info.get("version", "")

                    extr = f"{product} {version}".strip()
                    line = f"    - {port}/{proto} -> {state}"

                    if name:
                        line += f" ({name})"

                    if extr:
                        line += f" [{extr}]"

                    safe_print(ctx, line)

        safe_print(ctx, "[*] Scanning has been finished!")

    def custom_scan(self, ctx):
        target = input("Enter target IP/host: ").strip()
        ports = input("Enter ports (e.g., 22,80,443 or 1-1024): ").strip()

        nm = nmap.PortScanner()
        safe_print(ctx, f"\n[*] Custom scanning {target} on ports {ports}...")
        nm.scan(hosts=target, ports=ports)

        for host in nm.all_hosts():
            safe_print(ctx, f"[+] Host: {host} ({nm[host].hostname()})")

            for proto in nm[host].all_protocols():
                lports = sorted(nm[host][proto].keys())
                if not lports:
                    continue

                safe_print(ctx, f"  Protocol: {proto}")
                for port in lports:
                    port_info = nm[host][proto][port]
                    
                    state = port_info.get("state", "unknown")
                    name = port_info.get("name", "")

                    product = port_info.get("product", "")
                    version = port_info.get("version", "")

                    extr = f"{product} {version}".strip()
                    line = f"    - {port}/{proto} -> {state}"

                    if name:
                        line += f" ({name})"

                    if extr:
                        line += f" [{extr}]"

                    safe_print(ctx, line)

        safe_print(ctx, "[*] Scanning has been finished!")
# endregion

# region: override class: host2ip
def host2ip(ctx):
    safe_print(ctx, "[*] Host2IP selected.")
    raw = safe_input("Enter hostname(s) (comma-separated): ", ctx).strip()

    if not raw:
        safe_print(ctx, "[!] No hostname provided.")
        return

    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    try:
        dnspython_available = True
    except Exception:
        dnspython_available = False

    for host in hosts:
        safe_print(ctx, f"\n[*] Resolving: {host}")
        try:
            ips = []
            infos = socket.getaddrinfo(host, None)

            for info in infos:
                addr = info[4][0]
                if addr not in ips:
                    ips.append(addr)

            if ips:
                safe_print(ctx, f"[+] {host} -> {', '.join(ips)}")
            else:
                safe_print(ctx, f"[!] No addresses found for {host}")

            for ip in ips:
                try:
                    rev = socket.gethostbyaddr(ip)[0]
                    safe_print(ctx, f"    PTR: {ip} -> {rev}")
                except Exception:
                    pass

            if dnspython_available:
                try:
                    resolver = _dns_resolver.Resolver()
                    try:
                        mxs = resolver.resolve(host, "MX")
                        mx_list = ", ".join(sorted([str(r.exchange).rstrip('.') for r in mxs]))

                        safe_print(ctx, f"    MX: {mx_list}")
                    except Exception:
                        pass

                    try:
                        nss = resolver.resolve(host, "NS")
                        ns_list = ", ".join(sorted([str(r.target).rstrip('.') for r in nss]))
                        safe_print(ctx, f"    NS: {ns_list}")
                    except Exception:
                        pass
                except Exception:
                    pass

        except socket.gaierror as e:
            safe_print(ctx, f"[!] Cannot resolve {host}: {e}")
        except Exception as e:
            safe_print(ctx, f"[!] Unexpected error resolving {host}: {e}")

    safe_print(ctx, "[*] Host2IP: operation finished.")
# endregion

# region: override class: wpscan
class WPScan:
    menu_items = [
        "Interactive mode (guided scan)",
        "Quick scan (URL)",
        "Custom scan (manual args)",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] WPScan: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nWPScan options:")
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

        if sel == "Username enumeration":
            self.username_enumeration(ctx)
        elif sel == "Plugin enumeration":
            self.plugin_enumeration(ctx)
        elif sel == "All enumeration tools":
            self.all_enumeration_tools(ctx)

    def _get_wpscan_cmd(self):
        if shutil.which("wpscan"):
            return ["wpscan"]

        bundled = os.path.join(os.getcwd(), "tools", "wpscan", "wpscan.rb")
        if os.path.exists(bundled) and shutil.which("ruby"):
            return ["ruby", bundled]
        
        return None
    
    def _ensure_logs_dir(self):
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)

        return logs_dir
    
    def _make_logfile(self, prefix):
        logs_dir = self._ensure_logs_dir()
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        filename = f"{prefix}-{ts}.log"
        return os.path.join(logs_dir, filename)
    
    def _run_command_stream(self, cmd_list, log_path, ctx):
        try:
            with open(log_path, "w", encoding="utf-8", errors="ignore") as logf:
                logf.write("Command: " + " ".join(cmd_list) + "\n\n")
                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )

                if process.stdout is not None:
                    for line in process.stdout:
                        line = line.rstrip("\n")
                        safe_print(ctx, line)
                        logf.write(line + "\n")

                    process.wait()
                    return process.returncode
                else:
                    safe_print(ctx, "[!] No output from process.")
                    return -1
        except FileNotFoundError as e:
            safe_print(ctx, f"[!] Executable not found: {e}")
            return -1
        except Exception as e:
            safe_print(ctx, f"[!] Error running command: {e}")
            return -1

    def username_enumeration(self, ctx):
        target = safe_input("Enter target (URL or domain, e.g. https://example.com): ", ctx).strip()
        if not target:
            safe_print(ctx, "[!] Target required.")
            return
        
        wordlist = safe_input("Enter wordlist path (leave empty to use default): ", ctx).strip()
        wpscan_cmd = self._get_wpscan_cmd()

        if not wpscan_cmd:
            safe_print(ctx, "[!] wpscan/ruby not found in PATH and bundled script not available.")
            safe_print(ctx, "    Install wpscan or place tools/wpscan/wpscan.rb and ensure ruby is in PATH.")
            return

        logfile = self._make_logfile("wpscan-users")
        args = wpscan_cmd + ["--no-banner", "--random-user-agent", "--url", target, "--enumerate", "u", logfile]

        if wordlist:
            args += ["--wordlist", wordlist]

        safe_print(ctx, f"[*] Running username enumeration against {target}")
        safe_print(ctx, f"[*] Log: {logfile}")

        rc = self._run_command_stream(args, logfile, ctx)

        if rc == 0:
            safe_print(ctx, "[+] Username enumeration finished.")
        else:
            safe_print(ctx, f"[!] Enumeration finished with code {rc}.")

    def plugin_enumeration(self, ctx):
        target = safe_input("Enter target (URL or domain, e.g. https://example.com): ", ctx).strip()
        if not target:
            safe_print(ctx, "[!] Target required.")
            return

        wpscan_cmd = self._get_wpscan_cmd()
        if not wpscan_cmd:
            safe_print(ctx, "[!] wpscan/ruby not found in PATH and bundled script not available.")
            return

        logfile = self._make_logfile("wpscan-plugins")
        args = wpscan_cmd + ["--no-banner", "--random-user-agent", "--url", target, "--enumerate", "p", logfile]

        safe_print(ctx, f"[*] Running plugin enumeration against {target}")
        safe_print(ctx, f"[*] Log: {logfile}")

        rc = self._run_command_stream(args, logfile, ctx)
        
        if rc == 0:
            safe_print(ctx, "[+] Plugin enumeration finished.")
        else:
            safe_print(ctx, f"[!] Enumeration finished with code {rc}.")

    def all_enumeration_tools(self, ctx):
        target = safe_input("Enter target (URL or domain, e.g. https://example.com): ", ctx).strip()
        if not target:
            safe_print(ctx, "[!] Target required.")
            return

        wpscan_cmd = self._get_wpscan_cmd()
        if not wpscan_cmd:
            safe_print(ctx, "[!] wpscan/ruby not found in PATH and bundled script not available.")
            return

        logfile = self._make_logfile("wpscan-all")
        args = wpscan_cmd + ["--no-banner", "--random-user-agent", "--url", target, "--enumerate", "u,p,t", logfile]

        safe_print(ctx, f"[*] Running all enumeration (users, plugins, themes) against {target}")
        safe_print(ctx, f"[*] Log: {logfile}")

        rc = self._run_command_stream(args, logfile, ctx)

        if rc == 0:
            safe_print(ctx, "[+] All enumeration finished.")
        else:
            safe_print(ctx, f"[!] Enumeration finished with code {rc}.")
# endregion

# region: override class: CMS-Map
class CMSMap:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "CMSMap")

        self.git_repository = "https://github.com/Dionach/CMSmap.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        return os.path.isdir(self.install_direction) and os.path.exists(os.path.join(self.install_direction, "cmsmap.py"))

    def install(self):
        safe_print(self.ctx, "[*] Installing CMSMap...")
        
        os.system(f"git clone --depth=1 {self.git_repository} {self.install_direction}")
        os.system(f"pip install -r {os.path.join(self.install_direction, 'requirements.txt')}")

        safe_print(self.ctx, "[+] CMSMap installed successfully.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] CMSMap: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nCMSMap options:")
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
        safe_print(ctx, "\n[*] Starting CMSMap interactive session.")
        target = safe_input("Enter target (e.g. example.com or https://example.com): ", ctx).strip()
        if not target:
            safe_print(ctx, "[!] Target required.")
            return

        extra = safe_input("Extra CMSMap args (optional, e.g. -p 8080 -[...] {...}): ", ctx).strip()

        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_path = os.path.join(logs_dir, f"cmsmap-{ts}.txt")

        python_exec = shutil.which("python3") or shutil.which("python") or "python"
        cmsmap_script = os.path.join(self.install_direction, "cmsmap.py")

        if not os.path.exists(cmsmap_script):
            safe_print(ctx, f"[!] cmsmap.py not found at {cmsmap_script}")
            return

        cmd_parts = [python_exec, cmsmap_script, "-t", target]
        if extra:
            cmd_parts += extra.split()
        cmd_parts += ["-o", log_path]

        cmd = " ".join(cmd_parts)

        safe_print(ctx, f"[*] Executing: {cmd}")
        safe_print(ctx, f"[*] Log: {log_path}")

        try:
            os.system(cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Error running CMSMap: {e}")

        safe_input("\nPress Enter to return...", ctx)
# endregion

# region: override class: XSStrike
class XSStrike:
    menu_items = [
        "Run interactive mode",
        "Quick scan (URL)",
        "Custom scan (manual args)",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "XSStrike")

        self.git_repository = "https://github.com/UltimateHackers/XSStrike.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        return os.path.isdir(self.install_direction) and os.path.exists(os.path.join(self.install_direction, "xsstrike.py"))

    def install(self):
        safe_print(self.ctx, "[*] Installing XSStrike...")
        
        os.system(f"git clone --depth=1 {self.git_repository} {self.install_direction}")
        os.system(f"pip install -r {os.path.join(self.install_direction, 'requirements.txt')}")

        safe_print(self.ctx, "[+] XSStrike installed successfully.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] XSStrike: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nXSStrike options:")
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
        elif "quick" in sel:
            self.quick_scan(ctx)
        elif "custom" in sel:
            self.custom_scan(ctx)

    def run_interactive(self, ctx):
        safe_print(ctx, "\n[*] Starting XSStrike interactive session.")
        target = safe_input("Target URL (e.g. https://example.com): ", ctx).strip()
        if not target:
            safe_print(ctx, "[!] Target required.")
            return

        crawl = safe_input("Crawl site? (y/n): ", ctx).strip().lower()
        level = safe_input("Crawl depth level [1-3] (default 1): ", ctx).strip() or "1"
        blind = safe_input("Inject blind XSS payloads? (y/n): ", ctx).strip().lower()
        
        args = [f"-u {target}"]
        if crawl == "y":
            args.append("--crawl")
            args.append(f"-l {level}")
        if blind == "y":
            args.append("--blind")

        cmd = f"python {os.path.join(self.install_direction, 'xsstrike.py')} {' '.join(args)}"
        safe_print(ctx, f"[*] Executing: {cmd}")
        os.system(cmd)
        safe_input("Press Enter to return...", ctx)

    def quick_scan(self, ctx):
        target = safe_input("Enter target URL (e.g. https://example.com): ", self.ctx).strip()
        if not target:
            safe_print(self.ctx, "[!] Target required.")
            return

        safe_print(self.ctx, f"[*] Running XSStrike quick scan against {target}")
        cmd = f"python {os.path.join(self.install_direction, 'xsstrike.py')} -u {target}"
        os.system(cmd)

    def custom_scan(self, ctx):
        args = safe_input("Enter XSStrike arguments (e.g. -u https://site.com --crawl): ", self.ctx).strip()
        if not args:
            safe_print(self.ctx, "[!] No arguments provided.")
            return

        safe_print(self.ctx, f"[*] Running XSStrike with args: {args}")

        cmd = f"python {os.path.join(self.install_direction, 'xsstrike.py')} {args}"
        os.system(cmd)
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
        "Network mapper": Nmap,
        "Host2IP": host2ip,
        "WPScan": WPScan,
        "CMS-Map": CMSMap,
        "XSStrike": XSStrike
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