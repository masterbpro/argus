from bcc import BPF
import sys

interfaces = sys.argv[1:]
if not interfaces:
    print("Hint: python3 loader.py [interfaces]")
    sys.exit()

with open("bcc_ddos.c", "r") as file:
    program = file.read()

b = BPF(text=program)
fn = b.load_func("argus_count_packets", BPF.XDP)
b.attach_xdp(interfaces[0], fn)

print("Program succesfully attached")
