## Development guide

### Compile and run first eBPF program

**Development environment:**

- **Distributive**: `Debian 12 (bookworm)`
- **Linux Kernel**: `5.15.0-130-generic`
- **Architecture**: `x86_64 GNU/Linux`

```shell
apt install make
```

```shell
make
make build
make upload
# show bpf status
make list
# get bpf values
bpftool map dump id 1
```

### DoS

```shell
git clone https://github.com/MatrixTM/MHDDoS.git && cd MHDDoS
pip3 install -r requirements.txt
# run
python3 start.py TCP 10.0.0.2:80 8 30
python3 start.py get http://10.0.0.2 0 100 proxy.txt 100 30
```

---

### Useful links and materials

* https://docs.ebpf.io
* https://eunomia.dev/tutorials
* https://github.com/eunomia-bpf/bpf-developer-tutorial
* https://docs.cilium.io/en/stable/reference-guides/bpf/index.html
