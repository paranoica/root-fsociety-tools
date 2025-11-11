# region: outer menu operations
menu_name = "Sniff and spoof"
menu_items = [
    "SSLtrip",
    "pyPISHER",
    "SMTP Mailer"
]

menu_items.append("Back")
# endregion

# region: additonal imports
import os
import shutil
import subprocess

from colorama import Fore
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

# region: override class: ssltrip
class SSLtrip:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "SSLtrip")

        self.git_repository = "https://github.com/moxie0/sslstrip.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        return os.path.isdir(self.install_direction) and os.path.exists(os.path.join(self.install_direction, "ssltrip.py"))

    def install(self):
        safe_print(self.ctx, "[*] Installing SSLtrip...")
        os.system(f"git clone --depth=1 {self.git_repository} {self.install_direction}")

        req_file = os.path.join(self.install_direction, "requirements.txt")
        if os.path.exists(req_file):
            os.system(f"pip install -r {req_file}")

        safe_print(self.ctx, "[+] SSLtrip installed successfully.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] SSLtrip: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nSSLtrip options:")
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
        safe_print(ctx, "\n[*] Starting SSLtrip interactive session.\n")

        if not self.installed():
            safe_print(ctx, "[*] SSLtrip not installed. Installing now...")
            self.install()

        interface = safe_input("Enter network interface (default: eth0): ", ctx).strip() or "eth0"
        port = safe_input("Enter port to listen on (default: 8080): ", ctx).strip() or "8080"

        cmd = f"python {os.path.join(self.install_direction, 'sslstrip.py')} -l {port} -i {interface}"

        safe_print(ctx, f"[*] Running command:\n {cmd}\n")
        safe_print(ctx, "[!] Press Ctrl+C to stop SSLstrip\n")

        try:
            os.system(cmd)
        except KeyboardInterrupt:
            safe_print(ctx, "\n[*] SSLstrip session stopped by user.")

        safe_print(ctx, "\n[*] SSLtrip session finished.\n")
# endregion

# region: override class: pypisher
class PyPisher:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] PyPisher: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nPyPisher options:")
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
        safe_print(ctx, "\n[*] Starting pypisher session.\n")

        os.system("wget http://pastebin.com/raw/DDVqWp4Z --output-document=pisher.py")
        os.system("python pisher.py %s")

        safe_print(ctx, "\n[*] PyPisher session finished.\n")
# endregion

# region: override class: smtpfetcher
class SMTPFetcher:
    menu_items = [
        "Run interactive",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] SMTPFetcher: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nSMTPFetcher options:")
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
        safe_print(ctx, "\n[*] Starting smtpfetcher session.\n")

        os.system("wget http://pastebin.com/raw/Nz1GzWDS --output-document=smtp.py")
        os.system("python smtp.py %s")

        safe_print(ctx, "\n[*] SMTPFetcher session finished.\n")
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
        "SSLtrip": SSLtrip,
        "pyPISHER": PyPisher,
        "SMTP Mailer": SMTPFetcher
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