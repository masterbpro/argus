from bcc import BPF
from time import sleep


with open("bcc_ddos.c", "r") as file:
    program = file.read()

b = BPF(text=program)
fn = b.load_func("argus_count_packets", BPF.XDP)
b.attach_xdp("lo", fn)

print("Program succesfully attached")

while True:
    sleep(1)
    for i in b["ip_count_map"]:
        if b["ip_count_map"][i].count == 0:
            del b[i]
            continue
        b["ip_count_map"][i].count = 0

