Network Anomaly Investigation (Wireshark + Nmap)
📌 Overview
This investigation focused on understanding how different types of network traffic behave on the wire and how attackers might use these behaviors during reconnaissance. Using only Wireshark and Nmap, I simulated ICMP and HTTP traffic, captured the packets, analyzed the patterns, and scanned my own system to identify open ports and services. This project reinforces the fundamentals of threat hunting: observe, interpret, and understand before escalating.
________________________________________
🔍 Objectives
•	Capture and analyze ICMP and HTTP traffic
•	Identify protocol differences and behavioral patterns
•	Perform a host scan using Nmap
•	Determine which ports/services should be closed or reviewed
•	Strengthen foundational packet level awareness
________________________________________
📡 Traffic Generated
ICMP (Ping)
I generated continuous ICMP traffic using:
ping 1.1.1.1 -t
This created a steady flow of packets that revealed timing, frequency, and destination behavior. ICMP is simple, but it teaches the most important lesson in network analysis: observe the small details. If you miss the details, you misread the movement.
HTTP
I then generated HTTP traffic using:
curl http://example.com
Comparing HTTP to ICMP showed clear differences in packet structure, flow, and port usage. This matters because:
•	HTTP uses port 80
•	HTTPS uses port 443
Two different ports.
Two different flows.
Two different firewall rules.
If you don’t know which protocol you’re looking at, you can defend the wrong thing.
________________________________________
🔎 Nmap Scan Results
I scanned my own system to identify open ports and services. This revealed which services were active, which ports were exposed, and which areas needed review.
Ports that should NOT be open on a home network
•	23 (Telnet)
•	21 (FTP)
•	3389 (RDP)
•	445 (SMB)
•	135/139 (NetBIOS)
Ports that should be reviewed
•	80 (HTTP)
•	443 (HTTPS)
•	22 (SSH)
•	53 (DNS external exposure)
Normal home network ports
•	67/68 (DHCP)
•	53 (DNS local)
•	1900 (UPnP)
•	5353 (mDNS)
________________________________________
🧭 MITRE ATT&CK Mapping
MITRE ATT&CK mapping means matching observed behavior to known attacker techniques. It helps defenders understand intent, not just activity.
Relevant techniques:
•	T1046 – Network Service Scanning
•	T1071 – Application Layer Protocol
•	T1595 – Active Scanning
________________________________________
📝 Summary
During this investigation, I simulated ICMP and HTTP traffic, captured the packets in Wireshark, and analyzed how each protocol behaves on the wire. I then used Nmap to scan my own system and identify open ports and services that could expose a home network to unnecessary risk. This project reinforced the importance of mastering fundamentals — packet structure, protocol behavior, and port awareness — before relying on automated tools. By combining packet analysis with host scanning, I built a clearer picture of how attackers probe networks and how defenders can detect them early.
________________________________________
🏹 !Kung Proverb
“The tracker follows not the footprint, but the path the footprint belongs to.”
Meaning:
A single packet or port doesn’t tell the whole story. True defenders follow the behavior, not just the event. Tracking is about understanding movement, intent, and patterns — the same skills required in threat hunting.
