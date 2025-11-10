# region: imports
import os
import sys
import time
# endregion

# region: define variables
console_prompt = "root ~# "
menu_items = {
    "global": [
        "Information gathering",
        "Wireless testing",
        "Password attacks",
        "Web utilities",
        "Sniff and spoof",
        "Exploitation tools",
        "Post exploitation"
    ]
}
# endregion

# region: menu interaction
class menu:
    def __init__(self):
        self.run_menu("global")

    def clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def print_header(self):
        print(" ")
        print(
    '''
    mmmm                                    ##                                  
   ##"""                                    ""                 ##               
 #######   mm#####m   m####m    m#####m   ####      m####m   #######   "##  ### 
   ##      ##mmmm "  ##"  "##  ##"    "     ##     ##mmmm##    ##       ##m ##  
   ##       """"##m  ##    ##  ##           ##     ##""""""    ##        ####"  
   ##      #mmmmm##  "##mm##"  "##mmmm#  mmm##mmm  "##mmmm#    ##mmm      ###   
   ""       """"""     """"      """""   """"""""    """""      """"      ##    
                                                                        ###
    '''
        )

    def run_menu(self, menu_key):
        self.clear()
        self.print_header()

        if menu_key not in menu_items:
            time.sleep(1)
            self.run_menu("global")

            return
        
        items = menu_items[menu_key]

        print("\nSelect from the menu:\n")
        for i, it in enumerate(items, 1):
            print(f"[{i}] {it}")
        print("\n[0] Logout\n")

        choice = input(console_prompt).strip()

        if choice == "0":
            print("Finishing up...\n")

            time.sleep(0.5)
            sys.exit()

        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            print("Wrong paragraph...")

            time.sleep(0.25)
            self.__init__()

        idx = int(choice) - 1
        selected_item = items[idx]

        if selected_item.lower() == "back":
            self.run_menu("global")
            return
        
        if selected_item in menu_items:
            self.run_menu(selected_item)
            return

        self.run_menu(menu_key)
# endregion

# region: override main section
if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nFinishing up...\n")
        time.sleep(0.5)
# endregion