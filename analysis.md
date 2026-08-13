
# Malicious PCAP Investigation With Incident Report

## Incident Overview
This investigation analyzes a network packet capture associated
with a suspected compromise of a Windows workstation. Wireshark
was used to identify the affected host, analyze DNS, UDP, TCP,
TLS, HTTP, and QUIC traffic, reconstruct TCP Stream 40, and
identify indicators associated with NetSupport remote-access
software.


## 1. Victim Identification

IP Address: 10.2.28.88
MAC Address:14:b3:1f:2d:ce:69
Hostname: DESKTOP-TEYQ2NR 
User Account: brolf
User Full Name: Becka Rolf


## 2. DNS Analysis

### DNS Query #1

Source IP: 10.2.28.88

DNS Server: 10.2.28.2

Domain: easyas123-dc.easyas123.tech

Query Type: A 


### DNS Response

Response:
easyas123-dc.easyas123.tech → 10.2.28.2

### Observation

The DNS response observed in the PCAP associated the queried
domain with the internal DNS server address 10.2.28.2. The
connection to 45.131.214.85 was observed separately
and was not established as a direct DNS resolution of the domain
based on the available packet evidence.


## 3. UDP Analysis

### UDP Connection #1 — NTP

Source IP: 10.2.28.88
Destination IP: 10.2.28.2
Source Port: 123
Destination Port: 123
Protocol: UDP

### Observation

The workstation communicated with the internal host
10.2.28.2 using UDP port 123. UDP port 123 is used by
the Network Time Protocol (NTP) for system time
synchronization.


### UDP Connection #2 — NetBIOS 

Source IP: 10.2.28.88
Destination IP: 10.2.28.255
Source Port: 137
Destination Port: 137
Protocol: UDP

### Observation

The workstation sent UDP traffic to the local broadcast
address 10.2.28.255 on port 137. UDP port 137 is used by
NetBIOS Name Service (NBNS) for Windows name resolution
and local network discovery.



UDP Connection #3 — SSDP/UPnP

Source IP: 10.2.28.88
Destination IP: 239.255.255.250
Source Port: 57054
Destination Port: 1900
Protocol: UDP

### Observation

The workstation sent UDP traffic to the multicast address 239.255.255.250 on destination port 1900. The source port was 57054.
This port and multicast address are commonly associated with SSDP and UPnP device
and service discovery.


### UDP Connection #4 — CLDAP

Source IP: 10.2.28.88
Destination IP: 10.2.28.2
Source Port: 58447
Destination Port: 389
Protocol: CLDAP
Info: SearchRequest(97)<Root>baseObject

### Observation
The workstation sent a Connectionless LDAP (CLDAP)
SearchRequest to the internal host 10.2.28.2 over UDP
port 389.

CLDAP can be used by Windows systems for directory and
domain-controller discovery. The traffic is directed to
an internal host and appears consistent with normal
Windows domain activity.

### UDP Connection #5 — QUIC

Source IP: 10.2.28.88
Destination IP: 23.205.110.136
Source Port: 52124
Destination Port: 443
Protocol: QUIC
QUIC Version: IETF
Server Name Indication (SNI):
www.bing.com

### Observation
The workstation established a QUIC connection to
23.205.110.136 over UDP port 443. The QUIC Client Initial
packet contained the SNI www.bing.com.




## 4. TCP/TLS Analysis

### Connection 

Internal Host: 10.2.28.88
Remote Host: 45.131.214.85

Protocol: TCP

Internal Source Port: 51912
Remote Destination Port: 443

### TCP Handshake

1. SYN:
   10.2.28.88:51912 → 45.131.214.85:443

2. SYN/ACK:
   45.131.214.85:443 → 10.2.28.88:51912

3. ACK:
   10.2.28.88:51912 → 45.131.214.85:443

Application Data:
- Payload size: 440 bytes
- TCP Stream 40 contained an HTTP-POST request
- User-Agent: NetSupportManager/1.3


### Initial Observation

The internal host initiated a TCP connection to
45.131.214.85 over destination port 443.
Port 443 is commonly used for HTTPS/TLS traffic.
The TCP three-way handshake was successfully completed between 10.2.28.88:51912 and 45.131.214.85:443.


### TLS Connection — 20.189.173.2

Source: 10.2.28.88:54552
Destination: 20.189.173.2:443
Protocol: TLSv1.2

Server Name Indication (SNI):
v10.events.data.microsoft.com

### Observation

The suspected host established a TLS connection to
20.189.173.2. The TLS Client Hello contained the SNI
v10.events.data.microsoft.com, which is associated with
Microsoft telemetry/diagnostic services. However, this connection appears
consistent with legitimate Microsoft activity and is not
currently considered an indicator of compromise.


### TLS Connection — 20.190.157.9

Source: 10.2.28.88:54559
Destination: 20.190.157.9:443
Protocol: TLS

Server Name Indication (SNI):
login.microsoftonline.com

### Observation

The suspected host established a TLS connection to
20.190.157.9. The TLS Client Hello contained the SNI
login.microsoftonline.com, which is also associated with
Microsoft authentication services.


## 5. HTTP/HTTPS Analysis
## HTTP POST — TCP Stream 40

Source: 10.2.28.88
Destination: 45.131.214.85
Destination Port: 443

Method: POST
Host: 45.131.214.85
Request URI: /fakeurl.htm
User-Agent: NetSupportManager/1.3
Content-Length: 22 bytes

### Observation
TCP Stream 40 was reconstructed and contained an HTTP-formatted
POST request sent from the internal host to 45.131.214.85.

The request contained the User-Agent:
NetSupportManager/1.3.

The corresponding server response identified itself as:
NetSupport Gateway/1.92 (Windows NT).

The combination of the NetSupport-specific client User-Agent,
server identification, and repeated communication in TCP Stream
40 provides strong evidence of NetSupport remote-access software
communication.


### HTTP Response — TCP Stream 40

Source: 45.131.214.85
Destination: 10.2.28.88

Status: HTTP/1.1 200 OK

Server:
NetSupport Gateway/1.92 (Windows NT)
Content-Type:
application/x-www-form-urlencoded
Content-Length:
69 bytes
Response Data:
CMD=ENCD
ES=1
DATA= binary/encoded data

### Observation

The remote server responded with HTTP 200 OK and
identified itself as "NetSupport Gateway/1.92 (Windows NT)."
The response also contained the command "CMD=ENCD" followed
by encoded/binary data.

The server identification combined with the
NetSupportManager/1.3 User-Agent observed in the client
request provides strong evidence that this communication
is associated with NetSupport remote-access software.

### NetSupport Commands Observed

The reconstructed TCP stream contained the following commands:

- POLL
- ENCD (repeated)

The repeated ENCD messages contained encoded/binary data.
The POLL command is consistent with periodic communication
between a NetSupport client and remote infrastructure.


## 6. Suspicious Activity
The suspicious activity identified in the investigation was
communication between the internal workstation 10.2.28.88 and
the external IP address 45.131.214.85.

The connection was established over TCP port 443.The reconstruction of TCP
Stream 40 revealed HTTP POST communication.

The client identified itself with the User-Agent:
NetSupportManager/1.3.

The remote server identified itself as:
NetSupport Gateway/1.92 (Windows NT).

The stream also contained repeated ENCD messages and a POLL
command, with encoded/binary data exchanged between the hosts.

This activity is suspicious because the communication contains
multiple identifiers associated with NetSupport remote-access
software and establishes an external communication channel from
the internal workstation.

## 7. Indicators of Compromise

### Internal Host
- IP: 10.2.28.88
- Hostname: DESKTOP-TEYQ2NR
- User: brolf
- MAC: 14:b3:1f:2d:ce:69

### External IP
- 45.131.214.85

### Domain Observed
- easyas123-dc.easyas123.tech

### NetSupport Identifiers
- NetSupportManager/1.3
- NetSupport Gateway/1.92

### URI
- /fakeurl.htm




## 8. Incident Timeline

| Time | Event |
|---|---|
| Feb 28, 2026 2:55:08 | 10.2.28.88 queried DNS server 10.2.28.2 for easyas123-dc.easyas123.tech |
| Feb 28, 2026 2:55:51 | 10.2.28.88 initiated TCP connection to 45.131.214.85:443 |
| After TCP handshake | TCP Stream 40 contained reconstructed HTTP NetSupport communication |
| After connection | Server identified itself as NetSupport Gateway/1.92 and returned CMD=ENCD with encoded data |

## 9. Incident Assessment
The packet capture provides evidence that the workstation
DESKTOP-TEYQ2NR (10.2.28.88), associated with user account
brolf, communicated with external infrastructure at
45.131.214.85.

DNS activity involving easyas123-dc.easyas123.tech was observed
at 2:55:08, followed approximately 43 seconds later by a TCP
connection from the workstation to 45.131.214.85 on port 443.

TCP Stream 40 contained reconstructed HTTP communication
identifying the client as NetSupportManager/1.3 and the remote
server as NetSupport Gateway/1.92.

The available evidence is consistent with unauthorized or
potentially malicious use of NetSupport remote-access software.

## 10. Recommended Response

1. Isolate DESKTOP-TEYQ2NR (10.2.28.88) from the network.

2. Investigate the workstation for unauthorized NetSupport
   Manager installations, processes, services, scheduled tasks,
   and persistence mechanisms.

3. Block or monitor communication with the identified external
   IP address 45.131.214.85.

4. Investigate the domain:
   easyas123-dc.easyas123.tech

5. Review endpoint and authentication logs associated with
   user account brolf.

6. Search the environment for additional systems communicating
   with 45.131.214.85 or using the identified NetSupport
   identifiers.


## 11. Conclusion

Analysis of the provided PCAP identified DESKTOP-TEYQ2NR
(10.2.28.88) as the workstation involved in suspicious external
communication.

The most significant finding was TCP Stream 40, which contained
reconstructed HTTP communication between the workstation
and 45.131.214.85. The client identified itself as
NetSupportManager/1.3, while the remote server identified itself
as NetSupport Gateway/1.92 (Windows NT). The stream also contained
repeated ENCD messages and a POLL command with encoded data.

DNS activity for easyas123-dc.easyas123.tech was observed shortly
before the TCP connection.

Based on the available packet evidence, the communication is
consistent with NetSupport remote-access software and should be
treated as suspicious pending endpoint investigation.
Additional endpoint, process, authentication, and system-log
analysis would be required to fully determine the impact.


