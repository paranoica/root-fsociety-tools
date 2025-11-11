# region: outer menu operations
menu_name = "Password attacks"
menu_items = [
    "CUPP - Common User Passwords Profiler",
    "BruteX - Automatically bruteforces all services running on a target"
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

# region: override class: cupp
class CUPP:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "CUPP")

        self.git_repository = "https://github.com/Mebus/cupp.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        return os.path.isdir(self.tool_direction) or (os.path.isdir(self.install_direction) and os.path.exists(os.path.join(self.install_direction, "cupp.py")))

    def install(self):
        safe_print(self.ctx, "[*] Installing CUPP...")
        
        os.system(f"git clone --depth=1 {self.git_repository} {self.install_direction}")
        os.system(f"pip install -r {os.path.join(self.install_direction, 'requirements.txt')}")

        safe_print(self.ctx, "[+] CUPP installed successfully.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] CUPP: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nCUPP options:")
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
        safe_print(ctx, "\n[CUPP Interactive Mode]\n")

        if not self.installed():
            safe_print(ctx, "[!] CUPP is not installed. Attempting to install...")
            try:
                self.install()
            except Exception as e:
                safe_print(ctx, f"[!] Install error: {e}")
                return

        safe_print(ctx, "Enter arguments for cupp.py (leave empty to run interactive mode -i).")
        user_args = safe_input("cupp.py args: ", ctx).strip()

        if not user_args:
            user_args = "-i"

        cupp_py = os.path.join(self.install_direction, "cupp.py")
        if not os.path.exists(cupp_py):
            safe_print(ctx, "[!] cupp.py not found. Check installation.")
            return

        cmd_parts = [shutil.which("python") or "python", cupp_py] + user_args.split()
        final_cmd = " ".join(cmd_parts)

        safe_print(ctx, "\n[+] Built command:")
        safe_print(ctx, f"    {final_cmd}\n")

        confirm = safe_input("Run this command? (Y/n): ", ctx).strip().lower()
        if confirm and confirm in ("n", "no"):
            safe_print(ctx, "[*] Aborted by user.")
            return

        safe_print(ctx, "[*] Running CUPP...")
        try:
            os.system(final_cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Error while running: {e}")
        finally:
            safe_print(ctx, "[*] CUPP finished (or stopped).")
# endregion

# region: override class: brutex
class BruteX:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "BruteX")

        self.git_repository = "https://github.com/1N3/BruteX.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        return os.path.isdir(self.tool_direction) or (os.path.isdir(self.install_direction) and os.path.exists(os.path.join(self.install_direction, "brutex.py")))

    def install(self):
        safe_print(self.ctx, "[*] Installing BruteX...")

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
            safe_print(self.ctx, "[+] BruteX installed successfully.")
        else:
            safe_print(self.ctx, "[!] BruteX installation failed. Check output above.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] BruteX: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nBruteX options:")
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
        safe_print(ctx, "\n[BruteX Interactive Mode]\n")

        if not self.installed():
            safe_print(ctx, "[!] BruteX is not installed. Attempting to install...")
            try:
                self.install()
            except Exception as e:
                safe_print(ctx, f"[!] Install error: {e}")
                return

        safe_print(ctx, "Enter target IP or hostname for BruteX.")
        safe_print(ctx, "You can also add extra arguments (e.g., -u userlist -p passlist).")

        user_args = safe_input("Target IP and args: ", ctx).strip()
        if not user_args:
            safe_print(ctx, "[*] No input provided — aborting.")
            return

        brutex_py = os.path.join(self.install_direction, "brutex.py")
        if not os.path.exists(brutex_py):
            safe_print(ctx, "[!] brutex.py not found. Check installation.")
            return

        cmd_parts = [shutil.which("python") or "python", brutex_py] + user_args.split()
        final_cmd = " ".join(cmd_parts)

        safe_print(ctx, "\n[+] Built command:")
        safe_print(ctx, f"    {final_cmd}\n")

        confirm = safe_input("Run this command? (Y/n): ", ctx).strip().lower()
        if confirm and confirm in ("n", "no"):
            safe_print(ctx, "[*] Aborted by user.")
            return

        safe_print(ctx, "[*] Running BruteX...")
        try:
            os.system(final_cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Error while running: {e}")
        finally:
            safe_print(ctx, "[*] BruteX finished (or stopped).")
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
        "CUPP - Common User Passwords Profiler": CUPP,
        "BruteX - Automatically bruteforces all services running on a target": BruteX
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