# Wi-Fi Traffic Analysis

## Environment

- Linux virtual machine (VirtualBox)
- Hashcat
- hcxtools
- Wireshark

## Procedure

I extracted the handshake data from the capture file:

```bash
hcxpcapngtool -o handshake.hc22000 capture-7.pcap
```

I used a Hashcat mask attack based on the provided password policy:

```bash
hashcat -m 22000 -a 3 handshake.hc22000 'Acme?d?d?d?d?d?d'
```

I used the recovered password to decrypt the traffic in Wireshark and applied the following display filter:

```
http.request
```

I analysed the HTTP traffic and found the flag.

