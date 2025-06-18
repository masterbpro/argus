from bcc import BPF
import sys
from datetime import datetime

interfaces = sys.argv[1:]
if not interfaces:
    print("Hint: python3 loader.py [interface]")
    sys.exit()

with open("bcc_ddos.c", "r") as file:
    program = file.read()

b = BPF(text=program)

for key, value in b["ip_count_map"].items():
    if datetime.fromtimestamp(value.last_update / 1e9) + timedelta(seconds=600) < datetime.now():
        b["ip_count_map"].delete(key)

fn = b.load_func("argus_count_packets", BPF.XDP)
b.attach_xdp(interfaces[0], fn)

print("Program succesfully attached")
