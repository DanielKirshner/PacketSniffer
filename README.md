# PacketSniffer
## What is this?
Simple network packet sniffer, inspired by [tcpdump](https://github.com/the-tcpdump-group/tcpdump)
## Compatibility
Linux distributions that works with `apt` (Linux cli for package management).
I have been tested the packet sniffer on [Ubuntu 22.04](https://releases.ubuntu.com/22.04/)
## Requirements
A working network interface.
## Setup
Clone my project:
```
git clone https://github.com/DanielKirshner/PacketSniffer
```
Navigate to the project folder:
```
cd ./PacketSniffer
```
Run:
```
make
```
Now you will have the `packet_sniffer` program inside `bin` folder.
## Usage
Identify your network interface name by:
```
ifconfig -a
```
Run the packet sniffer with administrative privileges:
```
sudo ./bin/packet_sniffer.o [INTERFACE_NAME]
```