# SYN Spoof Scanner
A lightweight Python tool designed to perform SYN port scans, with support for using spoofed source IP addresses as a deception technique.

```
  ______   ___   _   ____                     __   ____
 / ___\ \ / / \ | | / ___| _ __   ___   ___  / _| / ___|  ___ __ _ _ __  _ __   ___ _ __
 \___ \\ V /|  \| | \___ \| '_ \ / _ \ / _ \| |_  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ___) || | | |\  |  ___) | |_) | (_) | (_) |  _|  ___) | (_| (_| | | | | | | |  __/ |
 |____/ |_| |_| \_| |____/| .__/ \___/ \___/|_|   |____/ \___\__,_|_| |_|_| |_|\___|_|
                          |_|

                                                            Author: Tier Zero Security - NZ

usage: syn_spoof_scanner.py [-h] -t TARGET [-p PORTS] [-F] [-s SOURCE_IP] [-i INTERFACE] [-ss SPOOFED_IPS] [-f FILE] [--open]

SYN Scan Tool with Optional Spoofed IPs, Multithreading, and Modes

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target IP address or comma-separated IPs/subnets
  -p PORTS, --ports PORTS
                        Comma-separated list of ports to scan
  -F, --fast            Perform a scan of the top 100 common ports (like Nmap)
  -s SOURCE_IP, --source-ip SOURCE_IP
                        Source IP address to use for scanning
  -i INTERFACE, --interface INTERFACE
                        Network interface to use for sending packets (e.g., eth0, wlan0)
  -ss SPOOFED_IPS, --spoofed-ips SPOOFED_IPS
                        Comma-separated list of spoofed source IPs
  -f FILE, --file FILE  File containing spoofed IPs (one per line)
  --open                Only display open ports
```

File spoofed IP example:

```
192.168.13.1
192.168.12.1,00:0c:29:b1:04:67
192.168.11.1,00:0c:29:b1:04:68
172.20.9.10,00:0c:29:b1:04:69
172.20.11.10,00:0c:29:b1:04:6a
172.20.12.10,00:0c:29:b1:04:6b
10.0.0.10,00:0c:29:b1:04:6c
```
