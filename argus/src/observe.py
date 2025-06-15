from bcc import BPF
from time import sleep
import ctypes as ct
import socket, struct
import ipaddress
from datetime import datetime
import sys

def get_ip_from_int(int_ip):
    ip = ipaddress.ip_address(int_ip)
    return ".".join(str(ip).split(".")[::-1])

#def display_table(bpf_object):
#    ip_map = bpf_object["ip_count_map"]
#    s = "\n===========\n"
#    s += "IP \t\t Count \t Last Ping\t\t Ban time\n"
#
#    for key, value in ip_map.items():
#        ip_str = get_ip_from_int(key.value)
#        last_ping_dt = datetime.utcfromtimestamp(value.last_ping / 1e9)
#        ban_time =  datetime.utcfromtimestamp(value.ban_time / 1e9)
#        s += f"{ip_str} \t {value.count} \t {last_ping_dt.strftime('%Y-%m-%d %H:%M:%S')}\t {ban_time.strftime('%Y-%m-%d %H:%M:%S')}\n"

#    s += "===========\n"
#    print(s)


with open("observe.c", "r") as file:
    program = file.read()

b = BPF(text=program)

try:
    command = sys.argv[1]
except Exception:
    sys.exit()

match command:
#    case "list":
#        display_table(b)    
    case "ban":
        try:
            arguments = sys.argv[2:]
        except Exception:
            pass
    case _:
        pass

