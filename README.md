# ROHC library - compress protocol headers

The ROHC library provides an easy and robust way for applications to reduce
their bandwidth usage on network links with limited capacity or expensive
costs. Headers of network packets are compressed with the ROHC protocol and
algorithms.

The ROHC protocol is very efficient for compressing VoIP streams that use RTP
as transport protocol. ROHC is also suitable for compressing IP-only (IPv4 or
IPv6), UDP or TCP flows and many others.

The ROHC library is intended for developers who want to reduce the bandwidth
requirements of their applications. Supported platforms include Linux, BSD,
Windows, and Android.


## Useful links

* Official website:      https://rohc-lib.org/
* Mailing list:          rohc@lists.launchpad.net
* Mailing list archives: https://lists.launchpad.net/rohc/
* Bugtracker:            https://bugs.launchpad.net/rohc


## License

The project is licensed under the GNU LGPL version 2.1 or later, see the
[COPYING](COPYING) and [AUTHORS.md](AUTHORS.md) files for more details.

Some network captures or small scripts used for testing are under the GNU GPL
version 2 or later.


## Sources organization

The sources of the ROHC library are located in the src/ subdirectory. They are
organized into subdirectories:
* `src/comp/` contains the sources of the ROHC compressor
  * `src/comp/schemes/` contains the sources of the compression schemes used
    by the ROHC compressor
* `src/decomp/` contains the sources of the ROHC decompressor
  * `src/decomp/schemes/` contains the sources of the compression schemes used
    by the ROHC decompressor
* `src/common/` contains the sources shared by the ROHC compressor and the ROHC
  decompressor
  * `src/common/protocols/` contains the definitions of some network headers.

The doxygen documentation is the main source of information to use the ROHC
library. The `examples` subdirectory also provides some examples.

See the [INSTALL.md](INSTALL.md) file to learn to build the ROHC library.


## Applications

Several applications are available in the `app/` subdirectory:
* `app/sniffer/` contains an application that allows developers to test the
  (de)compression of the ROHC library on any local network
* `app/stats/` contains an application that allows developers to compute some
  statistics about ROHC (de)compression of some network streams

See the [INSTALL.md](INSTALL.md) file to learn to build the ROHC applications.


## Python binding

As of version 2.0.0, a Python binding was added. It is not as CPU performant as
the C library, so it is only recommended for testing or rapid prototyping. See
the [INSTALL.md](INSTALL.md) file to learn building and installing the Python
binding.

The Python binding supports both Python 2.7 and Python 3.x.


## Tests

The `test/` subdirectory contains several test applications. See the
[INSTALL.md](INSTALL.md) file to learn how to use these tools.


## References

General:
* [ROHC library](https://rohc-lib.org/)
  The Open Source ROHC library described by the README file you are reading
* [ROHC Linux](http://rohc.sourceforge.net/)
  A GPL-licensed implementation of ROHC over PPP for the 2.4 Linux kernel.
  The ROHC library was based on this software
* [UDP-Lite](http://www.erg.abdn.ac.uk/users/gerrit/udp-lite/)
  An UDP-Lite implementation for the Linux kernel

IETF RFC:
* [RFC 3095](https://www.ietf.org/rfc/rfc3095.txt)
  ROHC: Framework and four profiles: RTP, UDP, ESP, and uncompressed
* [RFC 3096](https://www.ietf.org/rfc/rfc3096.txt)
  Requirements for robust IP/UDP/RTP header compression
* [RFC 3241](https://www.ietf.org/rfc/rfc3241.txt)
  ROHC over PPP
* [RFC 3242](https://www.ietf.org/rfc/rfc3242.txt)
  ROHC: A Link-Layer Assisted Profile for IP/UDP/RTP
* [RFC 3243](https://www.ietf.org/rfc/rfc3243.txt)
  ROHC: Requirements and Assumptions for 0-byte IP/UDP/RTP Compression
* [RFC 3408](https://www.ietf.org/rfc/rfc3408.txt)
  ROHC: Zero-byte Support for R-mode in Extended Link-Layer Assisted ROHC Profile
* [RFC 3409](https://www.ietf.org/rfc/rfc3409.txt)
  ROHC: Lower Layer Guidelines for Robust RTP/UDP/IP Header Compression
* [RFC 3759](https://www.ietf.org/rfc/rfc3759.txt)
  ROHC: Terminology and Channel Mapping Examples
* [RFC 3816](https://www.ietf.org/rfc/rfc3816.txt)
  ROHC: Definitions of Managed Objects (SNMP MIB) for ROHC
* [RFC 3828](https://www.ietf.org/rfc/rfc3828.txt)
  The Lightweight User Datagram Protocol (UDP-Lite)
* [RFC 3843](https://www.ietf.org/rfc/rfc3843.txt)
  ROHC: A Compression Profile for IP
* [RFC 4019](https://www.ietf.org/rfc/rfc4019.txt)
  ROHC: Profiles for User Datagram Protocol (UDP) Lite
* [RFC 4163](https://www.ietf.org/rfc/rfc4163.txt)
  ROHC: Requirements on TCP/IP Header Compression
* [RFC 4224](https://www.ietf.org/rfc/rfc4224.txt)
  ROHC over Channels That Can Reorder Packets
* [RFC 4362](https://www.ietf.org/rfc/rfc4362.txt)
  ROHC: A Link-Layer Assisted Profile for IP/UDP/RTP
* [RFC 4995](https://www.ietf.org/rfc/rfc4995.txt)
  The RObust Header Compression (ROHC) Framework
* [RFC 4996](https://www.ietf.org/rfc/rfc4996.txt)
  ROHC: A Profile for TCP/IP (ROHC-TCP)
* [RFC 4997](https://www.ietf.org/rfc/rfc4997.txt)
  Formal Notation for RObust Header Compression (ROHC-FN)
* [RFC 5225](https://www.ietf.org/rfc/rfc5225.txt)
  ROHCv2: Profiles for RTP, UDP, IP, ESP and UDP-Lite
* [RFC 5795](https://www.ietf.org/rfc/rfc5795.txt)
  The RObust Header Compression (ROHC) Framework
* [RFC 5856](https://www.ietf.org/rfc/rfc5856.txt)
  ROHC: Integration of ROHC over IPsec Security Associations
* [RFC 5857](https://www.ietf.org/rfc/rfc5857.txt)
  ROHC: IKEv2 Extensions to Support ROHC over IPsec
* [RFC 5858](https://www.ietf.org/rfc/rfc5858.txt)
  ROHC: IPsec Extensions to Support ROHC over IPsec
* [RFC 6846](https://www.ietf.org/rfc/rfc6846.txt)
  ROHC: A Profile for TCP/IP (ROHC-TCP)

