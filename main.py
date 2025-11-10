# region: imports
import os
import sys
import time

import importlib
from colorama import Fore, Style, init
# endregion

# region: import settings and etc.
init(autoreset=True)

modules = {}
def load_modules():
    global modules
    for file in os.listdir("modules"):
        if file.endswith(".py") and file != "__init__.py":
            name = file[:-3]
            mod = importlib.import_module(f"modules.{name}")

            if not hasattr(mod, "menu_name") or not hasattr(mod, "menu_items"):
                print(Fore.RED + f"[!] Module '{name}' is missing 'menu_name' or 'menu_items'")
                continue

            modules[mod.menu_name] = mod
load_modules()
# endregion

# region: define variables
console_prompt = Fore.LIGHTBLACK_EX + "root ~# " + Fore.LIGHTBLACK_EX
module_order = [
    "Information gathering",
    "Wireless testing",
    "Password attacks",
    "Web utilities",
    "Sniff and spoof",
    "Exploitation tools",
    "Post exploitation"
]

menu_items = {"global": [m for m in module_order if m in modules]}
for name, mod in modules.items():
    menu_items[name] = mod.menu_items
# endregion

# region: menu interaction
class menu:
    def __init__(self):
        self.path = ["~"]
        self.run_menu("global")

    def clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def print_header(self):
        print(Fore.MAGENTA + Style.BRIGHT + " ")
        print(
    Fore.RED + '''
    mmmm                                    ##                                  
   ##"""                                    ""                 ##               
 #######   mm#####m   m####m    m#####m   ####      m####m   #######   "##  ### 
   ##      ##mmmm "  ##"  "##  ##"    "     ##     ##mmmm##    ##       ##m ##  
   ##       """"##m  ##    ##  ##           ##     ##""""""    ##        ####"  
   ##      #mmmmm##  "##mm##"  "##mmmm#  mmm##mmm  "##mmmm#    ##mmm      ###   
   ""       """"""     """"      """""   """"""""    """""      """"      ##    
                                                                        ###
    ''' + Style.RESET_ALL)
        
    def print_pwd(self):
        path_str = Fore.GREEN + "/".join(self.path)
        print(f"\n{Fore.LIGHTBLACK_EX}[{Style.RESET_ALL}{path_str}{Fore.LIGHTBLACK_EX}]")

    def run_menu(self, menu_key):
        self.clear()

        self.print_header()
        self.print_pwd()

        if menu_key not in menu_items:
            time.sleep(1)
            return self.run_menu("global")
        
        items = menu_items[menu_key]

        print(Fore.LIGHTBLACK_EX + "Select from the menu:" + Style.RESET_ALL)
        for i, it in enumerate(items, 1):
            print(f"{Fore.LIGHTGREEN_EX}  [{i}]{Fore.LIGHTBLACK_EX} {it}")
        print(f"{Fore.LIGHTGREEN_EX}  [0]{Fore.LIGHTBLACK_EX} Logout\n")

        choice = input(console_prompt).strip()

        if choice == "0" or choice == "exit" or choice == "quit":
            print(Fore.RED + "Finishing up...\n")

            time.sleep(0.5)
            return sys.exit()

        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            self.__init__()

        idx = int(choice) - 1
        sel = items[idx]

        if sel.lower() == "back":
            if len(self.path) > 1:
                self.path.pop()
            return self.run_menu("global")

        if sel in menu_items:
            self.path.append(sel)
            return self.run_menu(sel)

        module = modules.get(menu_key)
        if module:
            self.path.append(sel)
            self.clear()

            self.print_header()
            self.print_pwd()

            try:
                context = {
                    "item": sel,
                    "prompt": console_prompt,

                    "print": lambda text, color=Fore.LIGHTBLACK_EX: print(color + text + Style.RESET_ALL),
                    "wprint": lambda text, color=Fore.RED: print(color + text + Style.RESET_ALL)
                }

                module.execute(context)
            except Exception as e:
                print(Fore.RED + f"[!] Error executing '{sel}': {e}")

            self.path.pop()
            input(Fore.LIGHTBLACK_EX + "\nPress Enter to return..." + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[!] Unknown module for key: {menu_key}")
            time.sleep(1)

        return self.run_menu(menu_key)
# endregion

# region: override main section
if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\nFinishing up...\n")
        time.sleep(0.5)
# endregion