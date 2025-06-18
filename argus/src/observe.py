from bcc import BPF
import ipaddress
import sys

def get_ip_from_int(int_ip):
    ip = ipaddress.ip_address(int_ip)
    return ".".join(str(ip).split(".")[::-1])

def display_table(table):
    s = "\n===========\n"
    s += "Banned IPs\n"
    s = "===========\n"
    for key in table.keys():
        ip_str = get_ip_from_int(key.value)
        s += f"{ip_str}\n"

    s += "===========\n"
    print(s)


with open("observe.c", "r") as file:
    program = file.read()

b = BPF(text=program)

try:
    command = sys.argv[1]
except Exception:
    sys.exit()

match command:
    case "list":
        display_table(b["ban_map"])    
    case "ban":
        try:
            arguments = sys.argv[2:]
        except Exception:
            print("Hint: python3 observe.py ban <ip>")
            sys.exit()
        for ip in arguments:
            b["ban_map"].items_update_batch(arguments, [1 for _ in arguments])
    case "unban":
        try:
            arguments = sys.argv[2:]
        except Exception:
            print("Hint: python3 observe.py unban <ip>")
            sys.exit()
        for ip in arguments:
            b["ban_map"].items_delete_batch(arguments)
    
    case _:
        pass

