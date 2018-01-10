## How to install the Wireshark plugin for the ROHC protocol

### Check whether Wireshark got Lua support

The ROHC plugin for Wireshark is implemented in Lua, so Wireshark shall be built
with the Lua support included.

Start Wireshark, go to the Help menu, then the About entry. The Lua word shall
appear in the list.

### Install ROHC dissectors in the Wireshark directory of the local user

```
$ make install
```

### Test with Wireshark

```
$ wireshark /path/to/rohc/sources/test/non_regression/rfc3095/inputs/ipv4/icmp/rohc_maxcontexts0_wlsb4_smallcid.pcap
```

### Test with tshark

```
$ tshark -V -r /path/to/rohc/sources/test/non_regression/rfc3095/inputs/ipv4/icmp/rohc_maxcontexts0_wlsb4_smallcid.pcap
```

