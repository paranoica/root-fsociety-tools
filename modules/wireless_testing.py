# region: outer menu operations
menu_name = "Wireless testing"
menu_items = [
    "--reaver",
    "--pixiewps",
    "Bluetooth Honeypot GUI Framework"
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

# region: override class: reaver
class Reaver:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "Reaver")

        self.git_repository = "https://github.com/t6x/reaver-wps-fork-t6x.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        reaver_py = os.path.join(self.install_direction, "reaver.py")
        reaver_bin = os.path.join(self.install_direction, "reaver")

        if os.path.exists(reaver_py) or os.path.exists(reaver_bin):
            return True

        if shutil.which("reaver"):
            return True

        return False

    def install(self):
        safe_print(self.ctx, "[*] Installing Reaver...")

        if not os.path.isdir(self.install_direction):
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
                safe_print(self.ctx, "[!] git not found on system. Please install git or clone manually.")
        else:
            git_dir = os.path.join(self.install_direction, ".git")
            if os.path.isdir(git_dir):
                safe_print(self.ctx, "[*] Repo already exists — attempting 'git pull' to update.")
                res = subprocess.run(["git", "-C", self.install_direction, "pull"], check=False, capture_output=True, text=True)

                if res.returncode != 0:
                    safe_print(self.ctx, f"[!] git pull failed: {res.stderr.strip() or res.stdout.strip()}")
                else:
                    safe_print(self.ctx, "[*] git pull completed.")
            else:
                safe_print(self.ctx, "[*] Install directory exists and is not a git repo — skipping clone.")

        req_file = os.path.join(self.install_direction, "requirements.txt")
        if os.path.exists(req_file):
            safe_print(self.ctx, "[*] Installing Python requirements (if any)...")

            res = subprocess.run([shutil.which("python") or "python", "-m", "pip", "install", "-r", req_file],
                                  check=False, capture_output=True, text=True)

            if res.returncode != 0:
                safe_print(self.ctx, f"[!] pip install failed: {res.stderr.strip() or res.stdout.strip()}")
            else:
                safe_print(self.ctx, "[*] requirements installed.")
        else:
            safe_print(self.ctx, "[*] No requirements.txt found — skipping pip install.")

        configure_path = os.path.join(self.install_direction, "configure")
        if os.path.exists(configure_path) and os.access(configure_path, os.X_OK):
            safe_print(self.ctx, "[*] Running configure && make (if present).")
            try:
                subprocess.run(["/bin/sh", "-c", f"cd {self.install_direction} && ./configure && make && sudo make install"],
                                check=False, capture_output=True, text=True)
            except Exception:
                pass

        if self.installed():
            safe_print(self.ctx, "[+] Reaver appears to be installed.")
        else:
            safe_print(self.ctx, "[!] Reaver not fully installed. Check the messages above.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Reaver: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nReaver options:")
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
        safe_print(ctx, "\n[Reaver Interactive Mode]\n")

        if not self.installed():
            safe_print(ctx, "[!] Reaver не установлен. Попытка установить...")
            try:
                self.install()
            except Exception as e:
                safe_print(ctx, f"[!] Ошибка установки: {e}")
                return

        interface = safe_input("Interface (e.g. wlan0 or mon0) [leave empty to cancel]: ", ctx).strip()
        if not interface:
            safe_print(ctx, "[*] Cancelled (no interface).")
            return

        bssid = safe_input("Target BSSID (AA:BB:CC:DD:EE:FF) [required]: ", ctx).strip()
        if not bssid:
            safe_print(ctx, "[!] BSSID is required. Aborting.")
            return

        channel = safe_input("Channel (optional, press Enter to skip): ", ctx).strip()
        pin = safe_input("Specific PIN (optional, press Enter to skip): ", ctx).strip()

        use_pixie = safe_input("Use pixiewps attack assist? (y/N): ", ctx).strip().lower()
        pixie_flag = False

        if use_pixie in ("y", "yes"):
            pixie_flag = True
            extra_pixie = safe_input("Extra pixiewps args (optional, press Enter to skip): ", ctx).strip()
        else:
            extra_pixie = ""

        extra_flags = safe_input("Any extra reaver flags (e.g. -vv -o output.log) [optional]: ", ctx).strip()
        cmd_parts = ["reaver"]

        reaver_py = os.path.join(self.install_direction, "reaver.py")
        reaver_bin = os.path.join(self.install_direction, "reaver")

        if os.path.exists(reaver_py):
            cmd_parts = ["python3", reaver_py]
        elif os.path.exists(reaver_bin):
            cmd_parts = [reaver_bin]
        else:
            cmd_parts = ["reaver"]

        cmd_parts += ["-i", interface]
        cmd_parts += ["-b", bssid]

        if channel:
            cmd_parts += ["-c", channel]

        if pin:
            cmd_parts += ["-p", pin]

        if pixie_flag:
            cmd_parts.append("-K")
            if extra_pixie:
                cmd_parts += extra_pixie.split()

        if extra_flags:
            cmd_parts += extra_flags.split()

        final_cmd = " ".join(cmd_parts)

        safe_print(ctx, "\n[+] Built command:")
        safe_print(ctx, f"    {final_cmd}\n")

        confirm = safe_input("Run this command? (Y/n): ", ctx).strip().lower()
        if confirm and confirm in ("n", "no"):
            safe_print(ctx, "[*] Aborted by user.")
            return

        safe_print(ctx, "[*] Запуск Reaver...")
        try:
            os.system(final_cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Ошибка при запуске: {e}")
        finally:
            safe_print(ctx, "[*] Reaver finished (or stopped).")
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
        "--reaver": Reaver
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