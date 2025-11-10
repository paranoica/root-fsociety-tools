menu_name = "Information gathering"
menu_items = [
    "Scan network",
    "Enumerate hosts",
    "Gather banners",
    "Back"
]

def execute(ctx):
    item = ctx["item"]
    fprint = ctx["print"]

    fprint(f"[*] Executing: {item}")