# Malicious-PCAP-Investigation





OVERVIEW



This project documents a network traffic investigation performed
using Wireshark on a PCAP associated with a suspected compromised
Windows workstation.
The investigation focused on identifying the affected host,
analyzing network protocols, reconstructing TCP communication,
identifying suspicious activity, extracting indicators of
compromise (IOCs), and developing incident response
recommendations.



OBJECTIVES

- Identify the potentially compromised workstation
- Analyze DNS, UDP, TCP, HTTP, TLS, and QUIC traffic
- Reconstruct suspicious TCP communication
- Identify potential indicators of compromise
- Build an incident timeline
- Develop recommended incident response actions



TOOLS
- Wireshark
- Git
- GitHub



KEY FINDINGS

The primary suspicious activity involved communication between
the internal workstation `10.2.28.88` and the external IP
`45.131.214.85`.

TCP Stream 40 contained HTTP-formatted communication identifying
the client as:
NetSupportManager/1.3

The remote server identified itself as:
NetSupport Gateway/1.92 (Windows NT)

The stream also contained `POLL` and repeated `ENCD` messages
with encoded/binary data.




SKILLS DEMONSTRATED

- Network traffic analysis
- Wireshark
- TCP/IP analysis
- DNS analysis
- HTTP analysis
- TLS/SNI analysis
- TCP stream reconstruction
- IOC identification
- Incident response
- Technical documentation





DISCLAIMER

This project was created for educational and portfolio purposes
using a provided PCAP file. The findings and conclusions are based
solely on the network traffic available within the capture.


