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
            safe_print(ctx, "[!] Reaver is not installed. Attempting to install...")
            try:
                self.install()
            except Exception as e:
                safe_print(ctx, f"[!] Install error: {e}")
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

        safe_print(ctx, "[*] Running Reaver...")
        try:
            os.system(final_cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Error while running: {e}")
        finally:
            safe_print(ctx, "[*] Reaver finished (or stopped).")
# endregion

# region: override class: pixie-wps
class PixieWPS:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "PixieWPS")

        self.git_repository = "https://github.com/wiire/pixiewps.git"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        pixie_wps_py = os.path.join(self.install_direction, "pixiewps.py")
        pixie_wps_bin = os.path.join(self.install_direction, "pixiewps")

        if os.path.exists(pixie_wps_py) or os.path.exists(pixie_wps_bin):
            return True

        if shutil.which("pixiewps"):
            return True

        return False

    def install(self):
        safe_print(self.ctx, "[*] Installing PixieWPS...")

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
            safe_print(self.ctx, "[+] PixieWPS appears to be installed.")
        else:
            safe_print(self.ctx, "[!] PixieWPS not fully installed. Check the messages above.")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] PixieWPS: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nPixieWPS options:")
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
        safe_print(ctx, "\n[PixieWPS Interactive Mode]\n")

        if not self.installed():
            safe_print(ctx, "[!] PixieWPS is not installed. Attempting to install...")
            try:
                self.install()
            except Exception as e:
                safe_print(ctx, f"[!] Install error: {e}")
                return

        safe_print(ctx, "Enter arguments for pixiewps (for example --help) or specific parameters.")
        safe_print(ctx, "If you plan to supply local parameters (E-Hash, nonces, etc.), enter them here.")
        safe_print(ctx, "Examples: --help or -e <e_hash1> -s <e_hash2> -z <something>\n")

        user_args = safe_input("pixiewps args: ", ctx).strip()
        if not user_args:
            safe_print(ctx, "[*] Empty input — cancelled.")
            return

        pixie_py = os.path.join(self.install_direction, "pixiewps.py")
        pixie_bin = os.path.join(self.install_direction, "pixiewps")

        if os.path.exists(pixie_py):
            cmd_parts = ["python3", pixie_py]
        elif os.path.exists(pixie_bin) and os.access(pixie_bin, os.X_OK):
            cmd_parts = [pixie_bin]
        elif shutil.which("pixiewps"):
            cmd_parts = [shutil.which("pixiewps")]
        else:
            cmd_parts = ["pixiewps"]

        cmd_parts += user_args.split()
        final_cmd = " ".join(cmd_parts)

        safe_print(ctx, "\n[+] Built command:")
        safe_print(ctx, f"    {final_cmd}\n")

        confirm = safe_input("Run this command? (Y/n): ", ctx).strip().lower()
        if confirm and confirm in ("n", "no"):
            safe_print(ctx, "[*] Aborted by user.")
            return

        safe_print(ctx, "[*] Running PixieWPS...")
        try:
            os.system(final_cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Error while running: {e}")
        finally:
            safe_print(ctx, "[*] PixieWPS finished (or stopped).")
# endregion

# region: override class: pixie-wps
class Bluepot:
    menu_items = [
        "Run interactive mode",
        "Back"
    ]
        
    def __init__(self, ctx=None):
        self.ctx = ctx or {}

        self.tool_direction = os.path.join(os.getcwd(), "tools")
        self.install_direction = os.path.join(self.tool_direction, "Bluepot")

        self.git_repository = "https://github.com/wiire/pixiewps.git"
        self.tar_ball_url = "https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz"

        if not os.path.isdir(self.tool_direction):
            os.makedirs(self.tool_direction, exist_ok=True)

        if not self.installed():
            self.install()

    def installed(self):
        jar_path = os.path.join(self.install_direction, "BluePot-0.1.jar")
        jar_bin_path = os.path.join(self.install_direction, "bin", "BluePot-0.1.jar")
        script_path = os.path.join(self.install_direction, "bluepot")

        if os.path.exists(jar_path) or os.path.exists(jar_bin_path) or os.path.exists(script_path):
            return True

        if shutil.which("bluepot"):
            return True

        for root, dirs, files in os.walk(self.install_direction):
            for f in files:
                if f.lower().startswith("bluepot") and f.lower().endswith(".jar"):
                    return True

        return False

    def install(self):
        safe_print(self.ctx, "[*] Installing Bluepot...")

        if not os.path.isdir(self.install_direction):
            try:
                res = subprocess.run(
                    ["git", "clone", "--depth=1", self.git_repository, self.install_direction],
                    check=False, capture_output=True, text=True
                )

                if res.returncode != 0:
                    safe_print(self.ctx, f"[!] git clone failed: {res.stderr.strip() or res.stdout.strip()}")
                    safe_print(self.ctx, "[*] Will attempt to download tarball fallback...")

                    os.makedirs(self.install_direction, exist_ok=True)
                    self._download_and_extract_tarball()
                else:
                    safe_print(self.ctx, "[*] git clone completed.")
            except FileNotFoundError:
                safe_print(self.ctx, "[!] git not found on system. Attempting tarball fallback.")
                os.makedirs(self.install_direction, exist_ok=True)

                self._download_and_extract_tarball()
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
                safe_print(self.ctx, "[*] Install directory exists and is not a git repo — skipping clone (will check contents).")

        if shutil.which("apt-get"):
            safe_print(self.ctx, "[*] Detected apt-get — attempting to install dependencies (may require sudo).")
            try:
                res = subprocess.run(["sudo", "apt-get", "-y", "update"], check=False, capture_output=True, text=True)
                if res.returncode != 0:
                    safe_print(self.ctx, f"[-] apt-get update returned non-zero: {res.stderr.strip() or res.stdout.strip()}")
                res = subprocess.run(["sudo", "apt-get", "-y", "install", "default-jre", "libbluetooth-dev"], check=False, capture_output=True, text=True)
                
                if res.returncode != 0:
                    safe_print(self.ctx, f"[!] apt-get install failed: {res.stderr.strip() or res.stdout.strip()}")
                else:
                    safe_print(self.ctx, "[*] System dependencies installed (or already present).")
            except Exception as e:
                safe_print(self.ctx, f"[!] Error while running apt-get: {e}")
        else:
            safe_print(self.ctx, "[*] apt-get not available — skipping system dependency install. Make sure Java and libbluetooth are installed manually if needed.")

        if self.installed():
            safe_print(self.ctx, "[+] Bluepot appears to be installed.")
        else:
            safe_print(self.ctx, "[!] Bluepot not fully installed. Check the messages above for hints.")

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
            safe_print(self.ctx, "[+] Bluepot appears to be installed.")
        else:
            safe_print(self.ctx, "[!] Bluepot not fully installed. Check the messages above.")

    def _download_and_extract_tarball(self):
        safe_print(self.ctx, f"[*] Downloading tarball from {self.tarball_url} ...")
        try:
            if shutil.which("wget"):
                cmd = ["wget", "-O", "-", self.tarball_url]

                p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                tar = subprocess.Popen(["tar", "xzf", "-"], cwd=self.install_direction, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                p1.stdout.close()
                out, err = tar.communicate()
                
                if tar.returncode != 0:
                    safe_print(self.ctx, f"[!] Tar extraction failed: {err.decode().strip() if isinstance(err, bytes) else err}")
                else:
                    safe_print(self.ctx, "[*] Tarball downloaded and extracted.")
            elif shutil.which("curl"):
                cmd = ["curl", "-L", self.tarball_url]
                
                p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                tar = subprocess.Popen(["tar", "xzf", "-"], cwd=self.install_direction, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                p1.stdout.close()
                out, err = tar.communicate()
                if tar.returncode != 0:
                    safe_print(self.ctx, f"[!] Tar extraction failed: {err.decode().strip() if isinstance(err, bytes) else err}")
                else:
                    safe_print(self.ctx, "[*] Tarball downloaded and extracted.")
            else:
                safe_print(self.ctx, "[!] Neither wget nor curl found — cannot download tarball automatically. Please clone the repo manually or download the tarball and extract into the tools/Bluepot directory.")
        except Exception as e:
            safe_print(self.ctx, f"[!] Download/extract error: {e}")

    def run(self, ctx):
        self.ctx = ctx
        safe_print(ctx, f"[*] Bluepot: selected '{ctx.get('item')}'")
        self.sub_menu(ctx)

    def sub_menu(self, ctx):
        safe_print(ctx, "\nBluepot options:")
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
        safe_print(ctx, "\n[Bluepot Interactive Mode]\n")

        if not self.installed():
            safe_print(ctx, "[!] Bluepot is not installed. Attempting to install...")
            try:
                self.install()
            except Exception as e:
                safe_print(self.ctx, f"[!] Install error: {e}")
                return

        jar_candidates = []
        for root, dirs, files in os.walk(self.install_direction):
            for f in files:
                if f.lower().startswith("bluepot") and f.lower().endswith(".jar"):
                    jar_candidates.append(os.path.join(root, f))

        jar_path = None
        if jar_candidates:
            jar_path = jar_candidates[0]
            safe_print(ctx, f"[*] Found BluePot jar: {jar_path}")
        else:
            p1 = os.path.join(self.install_direction, "BluePot-0.1.jar")
            p2 = os.path.join(self.install_direction, "bin", "BluePot-0.1.jar")

            if os.path.exists(p1):
                jar_path = p1
            elif os.path.exists(p2):
                jar_path = p2

        if not jar_path:
            script_exec = os.path.join(self.install_direction, "bluepot")
            if os.path.exists(script_exec) and os.access(script_exec, os.X_OK):
                safe_print(ctx, f"[*] Found bluepot executable: {script_exec}")
                use_exec = safe_input("Run executable directly? (Y/n): ", ctx).strip().lower()

                if use_exec in ("", "y", "yes"):
                    final_cmd = script_exec
                    safe_print(ctx, f"\n[+] Built command:\n    {final_cmd}\n")
                    confirm = safe_input("Run this command? (Y/n): ", ctx).strip().lower()

                    if confirm and confirm in ("n", "no"):
                        safe_print(ctx, "[*] Aborted by user.")
                        return

                    safe_print(ctx, "[*] Running Bluepot executable...")
                    try:
                        os.system(final_cmd)
                    except Exception as e:
                        safe_print(ctx, f"[!] Error while running: {e}")
                    finally:
                        safe_print(ctx, "[*] Bluepot finished (or stopped).")
                    return

            safe_print(ctx, "[!] Could not locate BluePot JAR or executable. Please check installation.")
            return

        safe_print(ctx, "How to run BluePot:")
        safe_print(ctx, "  [1] Run in foreground (normal)")
        safe_print(ctx, "  [2] Run with nohup and redirect output to file (background)")
        safe_print(ctx, "  [3] Run with custom java options")
        
        choice = safe_input("Choice [1]: ", ctx).strip()
        if choice == "":
            choice = "1"

        java_cmd = shutil.which("java") or "java"
        if not shutil.which("java"):
            safe_print(ctx, "[!] Java not found in PATH. You must install Java (JRE) to run BluePot.")
            proceed = safe_input("Attempt to run anyway? (y/N): ", ctx).strip().lower()
            if proceed not in ("y", "yes"):
                return

        if choice == "2":
            logfile = safe_input("Log file path (default bluepot.log): ", ctx).strip()
            if not logfile:
                logfile = "bluepot.log"
            final_cmd = f"nohup {java_cmd} -jar \"{jar_path}\" > \"{logfile}\" 2>&1 &"
        elif choice == "3":
            custom_opts = safe_input("Enter custom java options (e.g. -Xmx256m) and args: ", ctx).strip()
            final_cmd = f"{java_cmd} {custom_opts} -jar \"{jar_path}\""
        else:
            final_cmd = f"{java_cmd} -jar \"{jar_path}\""

        safe_print(ctx, "\n[+] Built command:")
        safe_print(ctx, f"    {final_cmd}\n")

        confirm = safe_input("Run this command? (Y/n): ", ctx).strip().lower()
        if confirm and confirm in ("n", "no"):
            safe_print(ctx, "[*] Aborted by user.")
            return

        safe_print(ctx, "[*] Running Bluepot...")
        try:
            os.system(final_cmd)
        except Exception as e:
            safe_print(ctx, f"[!] Error while running: {e}")
        finally:
            safe_print(ctx, "[*] Bluepot finished (or stopped).")
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
        "--reaver": Reaver,
        "--pixiewps": PixieWPS,
        "Bluetooth Honeypot GUI Framework": Bluepot
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