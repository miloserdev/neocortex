# neocortex

**neocortex** is an advanced eBPF/XDP-based packet filtering system that leverages neural networks to intelligently detect and mitigate suspicious or malicious network traffic in real time. Designed for high-performance environments, it operates directly in the kernel's data path, offering ultra-low latency and high throughput.

## Features

- High-speed packet inspection using XDP (eXpress Data Path)
- Neural network integration for adaptive DDoS and anomaly detection
- Real-time event reporting via BPF ring buffer or perf buffer
- Compatible with modern Linux kernels and Clang/LLVM toolchain

## Requirements

- Linux kernel with eBPF and XDP support
- Clang/LLVM (>= 12)
- libbpf
- iproute2 for loading programs (or custom loader)

## Used
- (emerging-all.rules) Ruleset is EmergingThreats Open optimized for snort-2.9.0-enhanced. (under GPLv2)
- libperceptron* perceptron and model by Andrew M (under GPLv2)

## Build and Run

```bash
make
```

# Tests
```bash
make kill ; make delete ; make clean ; make all ; make install
```

## Load
```bash
make install
```

## Unload
```bash
make delete
```

## Tools
```bash
bpftool map dump name ip_counter -p > dump.json
jq 'del(.[] | .formatted)' dump.json > raw.json
```

```bash
ip link add xdp-remote type veth peer name xdp-local
ip netns add xdp-test
ip link set dev xdp-remote netns xdp-test
ip netns exec xdp-test  ip address add 192.0.2.2/24 dev xdp-remote
ip netns exec xdp-test  ip link set xdp-remote up
ip address add 192.0.2.1/24 dev xdp-local
ip link set xdp-local up
```

```bash
tcpdump -i xdp-local

echo -n 1 | sudo tee /sys/kernel/debug/tracing/options/trace_printk
cat /sys/kernel/debug/tracing/trace_pipe
```

## Tests
```bash
printf "%b" '\x65\x7a\x69\x70\x3a\x2f\x2f\x62\x6c\x61\x2f\x62\x6c\x61\x3f\x53\x4e\x3d\x62\x6c\x61\x3f\x50\x4e\x3d\x62\x6c\x61\x3f\x55\x4e\x3d\x62\x6c\x61' > attack_file.bin

printf "%b" '\x65\x7a\x69\x70\x3a\x2f\x2f\x62\x6c\x61\x2f\x62\x6c\x61\x3f\x53\x4e\x3d\x62\x6c\x61\x3f\x50\x4e\x3d\x62\x6c\x61\x3f\x55\x4e\x3d\x62\x6c\x61\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > attack_file.bin

printf "%b" '\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x32\x30\x30\x20\x4f\x4b\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69' > ok_file.bin

ip netns exec xdp-test   hping3 -S -p 80 -i u50000 192.0.2.1 -c 1 --data 32 --file ./attack_file.bin
```

## Autotests
```bash
# generate binaries from rules
python3 make_bins.py ../rules/emerging-all.rules ./bins 10

# generate script from binaries
python3 make_script.py ./bins attacks.sh 192.0.2.1
```