🔴 RED TEAM REPORT
NightFall Project #1 – Living‑Off‑the‑Land (LOTL) Attack Simulation
1. Overview
This red‑team simulation replicates a realistic adversary abusing native Windows tools to perform malicious activity without deploying traditional malware. The goal is to generate telemetry that mirrors real attacker behavior, enabling the Blue Team to detect, analyze, and respond to fileless PowerShell‑based activity.
The simulation focuses on PowerShell abuse, encoded command execution, process creation anomalies, and network activity consistent with command‑and‑control (C2).

2. Objectives
The red‑team activity was designed to:
• 	Demonstrate how attackers leverage built‑in Windows utilities to evade detection
• 	Generate encoded or obfuscated PowerShell execution
• 	Produce process creation events that resemble reconnaissance or lateral movement
• 	Simulate outbound network beaconing
• 	Provide realistic telemetry for threat hunting and detection engineering
No harmful payloads or malicious binaries were used.
All activity was safe and controlled.

3. Hypothesis
“An attacker may be using PowerShell or other native Windows utilities to execute payloads or perform malicious actions without writing files to disk.”
This hypothesis guided the simulation toward behaviors commonly seen in real LOTL intrusions.

4. Logging Configuration
To ensure full visibility into attacker behavior, the following logging mechanisms were enabled:
PowerShell Logging
• 	Script Block Logging
Captures full PowerShell command content, including hidden or obfuscated commands.
• 	Module Logging
Records which PowerShell modules were invoked.
Windows Security Logs
• 	Process creation
• 	Logon activity
Sysmon (Optional but recommended)
• 	Event ID 1 – Detailed process creation
• 	Event ID 3 – Network connections
This configuration ensures that all PowerShell activity — including encoded commands — is captured and available for analysis.

5. Simulated Attacker Activity
The red‑team simulation generated the following behaviors:
5.1 Fileless PowerShell Execution
PowerShell was used to mimic fileless techniques commonly seen in real attacks.
This included suspicious command‑line parameters and encoded execution patterns.
5.2 Encoded / Obfuscated Commands
Encoded PowerShell commands were executed to simulate adversaries attempting to hide intent and evade detection.
5.3 Process Creation Anomalies
PowerShell spawned with unusual parent/child relationships, consistent with attacker tradecraft.
5.4 Simulated Command‑and‑Control (C2) Beaconing
A continuous outbound network request was generated to mimic malware “calling home.”
This produced:
• 	Persistent PowerShell activity
• 	Repeated outbound connections
• 	Observable Sysmon Event ID 3 entries
This telemetry becomes a key detection point for the Blue Team.

6. MITRE ATT&CK Mapping (Red Team Perspective)
TA0001 – Initial Access
• 	T1078 – Valid Accounts
Assumes attacker already has access and is using legitimate credentials.
TA0002 – Execution
• 	T1059.001 – PowerShell
• 	T1059 – Command and Scripting Interpreter
TA0005 – Defense Evasion
• 	T1027 – Obfuscated/Encrypted Files or Information
• 	T1055 – Process Injection (Optional)
• 	T1562.004 – Modify System Logging (Optional)
TA0007 – Discovery
• 	T1082 – System Information Discovery
• 	T1083 – File and Directory Discovery
• 	T1049 – System Network Connections Discovery
• 	T1018 – Remote System Discovery
TA0011 – Command and Control
• 	T1071.001 – Web Protocols
Simulated outbound beaconing.
(Optional techniques such as persistence, privilege escalation, credential access, and exfiltration may be included depending on the scope.)

7. Key Red Team Insights
• 	LOTL attacks rely on blending in, not dropping malware.
• 	PowerShell is one of the most abused native tools in Windows environments.
• 	Encoded commands are a major detection opportunity.
• 	Sysmon dramatically increases visibility into attacker behavior.
• 	Even simple outbound traffic can mimic C2 beaconing patterns.
This simulation successfully produced realistic attacker telemetry for the Blue Team to investigate.

8. Red Team Summary
The red‑team activity generated:
• 	Suspicious PowerShell execution
• 	Encoded command activity
• 	Parent/child process anomalies
• 	Outbound network connections
• 	Indicators consistent with reconnaissance and early‑stage intrusion
