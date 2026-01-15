# NightFall-Project-01-LOTL-Detection
Living-Off-the-Land (LOTL) attack detection using native Windows tools. Red Team + Blue Team investigation with MITRE ATT&amp;CK mapping.
FULL RED TEAM REPORT 
Living Off the Land (LOTL) Attack Simulation
1. Overview
This red team simulation replicates a realistic attacker using native Windows tools to perform malicious activity without deploying traditional malware. The objective is to generate telemetry that reflects common adversary tradecraft, enabling the Blue Team to detect, analyze, and respond to fileless PowerShell based activity.
________________________________________
2. Objectives
•	Demonstrate how attackers abuse PowerShell and built in Windows utilities
•	Generate encoded/obfuscated PowerShell execution
•	Produce process creation and network connection events
•	Simulate command and control (C2) beaconing
•	Provide realistic telemetry for threat hunting and detection engineering
________________________________________
3. Hypothesis
“An attacker may be using PowerShell or other native Windows utilities to execute payloads or perform malicious actions without writing files to disk.”
________________________________________
4. Logging Configuration
To ensure full visibility into attacker behavior, the following logs were enabled:
•	PowerShell Script Block Logging
•	PowerShell Module Logging
•	Windows Security Logs (Process Creation)
•	Sysmon Event ID 1 (Process Creation)
•	Sysmon Event ID 3 (Network Connections)
This configuration ensures that all PowerShell activity — including hidden, encoded, or obfuscated commands — is captured.
________________________________________
5. Simulated Attacker Activity
The red team simulation included:
•	Executing PowerShell commands designed to mimic fileless techniques
•	Triggering encoded or obfuscated command execution
•	Generating suspicious process creation events
•	Producing outbound network traffic to simulate C2 beaconing
No harmful payloads were used.
All activity was designed to safely replicate attacker behavior for detection and analysis.
________________________________________
6. Simulated C2 Beaconing
A continuous outbound network request was generated to mimic malware “calling home.”
This produced:
•	Persistent PowerShell activity
•	Repeated outbound connections
•	Observable Sysmon Event ID 3 entries
This telemetry becomes a key detection point for the Blue Team.
________________________________________
7. MITRE ATT&CK Mapping (Red Team Perspective)
Tactic	Technique	Description
Initial Access	T1078	Use of valid credentials/session
Execution	T1059.001	PowerShell execution
Execution	T1059	Command interpreter abuse
Defense Evasion	T1027	Encoded/obfuscated commands
Discovery	T1082	System information discovery
Discovery	T1083	File/directory enumeration
Discovery	T1049	Network connection discovery
Discovery	T1018	Remote system discovery
Command & Control	T1071.001	Web protocol beaconing
Optional techniques (persistence, privilege escalation, credential access, exfiltration) may be included depending on the simulation scope.
8. Red Team Summary
The red team simulation successfully generated realistic LOTL telemetry, including:
•	Suspicious PowerShell execution
•	Encoded command activity
•	Parent/child process anomalies
•	Outbound network connections
•	Indicators consistent with attacker reconnaissance
This telemetry provides the foundation for the Blue Team investigation.

FULL BLUE TEAM REPORT Final
Detection, Analysis, and Response to LOTL Activity
1. Overview
The Blue Team conducted a full investigation into suspicious PowerShell activity identified through host based logs. The goal was to validate the hypothesis, identify indicators of compromise, reconstruct the attacker timeline, and determine the scope and impact of the simulated breach.

2. Detection Summary
Initial detection was triggered by:
•	PowerShell Script Block Logging showing encoded command execution
•	Sysmon Event ID 1 indicating suspicious PowerShell parent/child processes
•	Sysmon Event ID 3 showing repeated outbound network connections
•	Windows Security Logs confirming process creation anomalies
These events aligned with known LOTL attack patterns.

3. Investigation Steps
3.1 PowerShell Operational Logs
Analysts observed:
•	Encoded or obfuscated commands
•	Script blocks inconsistent with normal user activity
•	Module usage indicative of reconnaissance
These findings supported the hypothesis of malicious PowerShell activity.

3.2 Sysmon Event ID 1 – Process Creation
Sysmon logs revealed:
•	PowerShell launched with suspicious parameters
•	Parent process relationships inconsistent with normal workflows
•	Execution patterns matching known attacker behavior
This confirmed that PowerShell was being used as the primary execution vector.

3.3 Sysmon Event ID 3 - Network Connections
Outbound network connections were observed:
•	Repeated connections to an external IP
•	Consistent timing indicative of beaconing
•	No legitimate process justification
This behavior aligned with simulated C2 activity.

3.4 Windows Security Logs
Security logs provided:
•	Process creation events
•	User context validation
•	Confirmation that no privilege escalation occurred
These logs helped validate the timeline and scope.

4. Timeline of Events (Blue Team Reconstruction)
Time	Event	Log Source
T0	PowerShell launched with suspicious parameters	Sysmon ID 1
T0+1	Script block logging captures encoded command	PowerShell Operational
T0+5	Outbound network connection initiated	Sysmon ID 3
T0+5–T0+65	Repeated outbound connections (beaconing)	Sysmon ID 3
T0+10	Additional PowerShell module activity	PowerShell Operational
T0+15	Security log confirms process creation	Windows Security Log
This timeline mirrors common attacker behavior in LOTL intrusions.

5. Indicators of Compromise (IOCs)
(You will attach screenshots in your Evidence Enclosure)
•	Suspicious PowerShell script blocks
•	Encoded command execution
•	Unusual parent/child process relationships
•	Repeated outbound network connections
•	PowerShell activity outside normal user behavior

6. Impact Assessment
The simulated activity demonstrated:
•	Potential for fileless malware execution
•	Ability to perform reconnaissance
•	Ability to establish outbound communication
•	Risk of lateral movement if not detected
No actual data was accessed or exfiltrated.

7. Recommendations
Detection
•	Enable Script Block Logging and Module Logging across endpoints
•	Deploy Sysmon with a hardened configuration
•	Create alerts for encoded PowerShell commands
•	Monitor for abnormal parent/child process relationships
Prevention
•	Restrict PowerShell usage to authorized users
•	Enforce PowerShell Constrained Language Mode
•	Implement application control policies
Response
•	Investigate all encoded PowerShell activity
•	Review outbound network connections for anomalies
•	Validate user account activity for legitimacy

8. Blue Team Summary
The Blue Team successfully detected, analyzed, and reconstructed the simulated LOTL attack.
The investigation confirmed:
•	PowerShell was used for suspicious activity
•	Outbound network connections resembled C2 behavior
•	Logging captured all relevant telemetry
•	The hypothesis was validated
This demonstrates effective detection and response capability using native Windows tools.
