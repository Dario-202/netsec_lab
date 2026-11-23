## Task 2 – Alternative solution using TShark

The challenge can also be solved without writing a Python script,
since TShark automatically calculates JA4 fingerprints.

### 1. Extract the reference JA4 fingerprint

```powershell
& "C:\Program Files\Wireshark\tshark.exe" --% -r .\lab2\capture-7.2.pcap -Y "tls.handshake.extensions_server_name contains \"syncbridge.example\"" -T fields -e tls.handshake.ja4
```

This command extracts the JA4 fingerprint of the connection
associated with the known C2 domain.

### 2. Identify connections with the same JA4 fingerprint

```powershell
& "C:\Program Files\Wireshark\tshark.exe" --% -r .\lab2\capture-7.2.pcap -Y "tls.handshake.ja4 == "JA4"" -T fields -e tls.handshake.extensions_server_name
```

This command extracts the SNI values of all connections with the same JA4 fingerprint.

### 3. Generate the flag

Extract the first six-character hexadecimal label from each of
the eight SNI values and concatenate them in capture order.

The resulting flag has the following format:

`netsec{<48 hexadecimal characters>}`
