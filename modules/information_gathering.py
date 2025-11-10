# region: outer menu operations
menu_name = "Information gathering"
menu_items = [
    "Network mapper",
    "SE-Toolkit",
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
import time
import nmap # type: ignore
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
    try:
        inp = input
        return inp(prompt)
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
    host = safe_input("Enter hostname: ", ctx).strip()
    safe_print(ctx, f"[+] {host} -> 192.0.2.1 (fake result)")
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
        "Host2IP": host2ip
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