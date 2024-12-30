import random
import customtkinter as ctk
from tkinter import messagebox, StringVar




# Acronym data
acronym_list = [
    ("AAA", "Authentication, Authorization, and Accounting"),
    ("ACL", "Access Control List"),
    ("AES", "Advanced Encryption Standard"),
    ("AES-256", "Advanced Encryption Standards 256-bit"),
    ("AH", "Authentication Header"),
    ("AI", "Artificial Intelligence"),
    ("AIS", "Automated Indicator Sharing"),
    ("ALE", "Annualized Loss Expectancy"),
    ("AP", "Access Point"),
    ("API", "Application Programming Interface"),
    ("APT", "Advanced Persistent Threat"),
    ("ARO", "Annualized Rate of Occurrence"),
    ("ARP", "Address Resolution Protocol"),
    ("ASLR", "Address Space Layout Randomization"),
    ("ATT&CK", "Adversarial Tactics, Techniques, and Common Knowledge"),
    ("AUP", "Acceptable Use Policy"),
    ("AV", "Antivirus"),
    ("BASH", "Bourne Again Shell"),
    ("BCP", "Business Continuity Planning"),
    ("BGP", "Border Gateway Protocol"),
    ("BIA", "Business Impact Analysis"),
    ("BIOS", "Basic Input/Output System"),
    ("BPA", "Business Partners Agreement"),
    ("BPDU", "Bridge Protocol Data Unit"),
    ("BYOD", "Bring Your Own Device"),
    ("CA", "Certificate Authority"),
    ("CAPTCHA", "Completely Automated Public Turing Test to Tell Computers and Humans Apart"),
    ("CAR", "Corrective Action Report"),
    ("CASB", "Cloud Access Security Broker"),
    ("CBC", "Cipher Block Chaining"),
    ("CCMP", "Counter Mode/CBC-MAC Protocol"),
    ("CCTV", "Closed-circuit Television"),
    ("CERT", "Computer Emergency Response Team"),
    ("CFB", "Cipher Feedback"),
    ("CHAP", "Challenge Handshake Authentication Protocol"),
    ("CIA", "Confidentiality, Integrity, Availability"),
    ("CIO", "Chief Information Officer"),
    ("CIRT", "Computer Incident Response Team"),
    ("CMS", "Content Management System"),
    ("COOP", "Continuity of Operation Planning"),
    ("COPE", "Corporate Owned, Personally Enabled"),
    ("CP", "Contingency Planning"),
    ("CRC", "Cyclical Redundancy Check"),
    ("CRL", "Certificate Revocation List"),
    ("CSO", "Chief Security Officer"),
    ("CSP", "Cloud Service Provider"),
    ("CSR", "Certificate Signing Request"),
    ("CSRF", "Cross-site Request Forgery"),
    ("CSU", "Channel Service Unit"),
    ("CTM", "Counter Mode"),
    ("CTO", "Chief Technology Officer"),
    ("CVE", "Common Vulnerability Enumeration"),
    ("CVSS", "Common Vulnerability Scoring System"),
    ("CYOD", "Choose Your Own Device"),
    ("DAC", "Discretionary Access Control"),
    ("DBA", "Database Administrator"),
    ("DDoS", "Distributed Denial of Service"),
    ("DEP", "Data Execution Prevention"),
    ("DES", "Digital Encryption Standard"),
    ("DHCP", "Dynamic Host Configuration Protocol"),
    ("DHE", "Diffie-Hellman Ephemeral"),
    ("DKIM", "DomainKeys Identified Mail"),
    ("DLL", "Dynamic Link Library"),
    ("DLP", "Data Loss Prevention"),
    ("DMARC", "Domain Message Authentication Reporting and Conformance"),
    ("DNAT", "Destination Network Address Translation"),
    ("DNS", "Domain Name System"),
    ("DoS", "Denial of Service"),
    ("DPO", "Data Privacy Officer"),
    ("DRP", "Disaster Recovery Plan"),
    ("DSA", "Digital Signature Algorithm"),
    ("DSL", "Digital Subscriber Line"),
    ("EAP", "Extensible Authentication Protocol"),
    ("ECB", "Electronic Code Book"),
    ("ECC", "Elliptic Curve Cryptography"),
    ("ECDHE", "Elliptic Curve Diffie-Hellman Ephemeral"),
    ("ECDSA", "Elliptic Curve Digital Signature Algorithm"),
    ("EDR", "Endpoint Detection and Response"),
    ("EFS", "Encrypted File System"),
    ("ERP", "Enterprise Resource Planning"),
    ("ESN", "Electronic Serial Number"),
    ("ESP", "Encapsulated Security Payload"),
    ("FACL", "File System Access Control List"),
    ("FDE", "Full Disk Encryption"),
    ("FIM", "File Integrity Management"),
    ("FPGA", "Field Programmable Gate Array"),
    ("FRR", "False Rejection Rate"),
    ("FTP", "File Transfer Protocol"),
    ("FTPS", "Secured File Transfer Protocol"),
    ("GCM", "Galois Counter Mode"),
    ("GDPR", "General Data Protection Regulation"),
    ("GPG", "Gnu Privacy Guard"),
    ("GPO", "Group Policy Object"),
    ("GPS", "Global Positioning System"),
    ("GPU", "Graphics Processing Unit"),
    ("GRE", "Generic Routing Encapsulation"),
    ("HA", "High Availability"),
    ("HDD", "Hard Disk Drive"),
    ("HIDS", "Host-based Intrusion Detection System"),
    ("HIPS", "Host-based Intrusion Prevention System"),
    ("HMAC", "Hashed Message Authentication Code"),
    ("HOTP", "HMAC-based One-time Password"),
    ("HSM", "Hardware Security Module"),
    ("HTML", "Hypertext Markup Language"),
    ("HTTP", "Hypertext Transfer Protocol"),
    ("HTTPS", "Hypertext Transfer Protocol Secure"),
    ("HVAC", "Heating, Ventilation Air Conditioning"),
    ("IaaS", "Infrastructure as a Service"),
    ("IaC", "Infrastructure as Code"),
    ("IAM", "Identity and Access Management"),
    ("ICMP", "Internet Control Message Protocol"),
    ("ICS", "Industrial Control Systems"),
    ("IDEA", "International Data Encryption Algorithm"),
    ("IDF", "Intermediate Distribution Frame"),
    ("IdP", "Identity Provider"),
    ("IDS", "Intrusion Detection System"),
    ("IEEE", "Institute of Electrical and Electronics Engineers"),
    ("IKE", "Internet Key Exchange"),
    ("IM", "Instant Messaging"),
    ("IMAP", "Internet Message Access Protocol"),
    ("IoC", "Indicators of Compromise"),
    ("IoT", "Internet of Things"),
    ("IP", "Internet Protocol"),
    ("IPS", "Intrusion Prevention System"),
    ("IPSec", "Internet Protocol Security"),
    ("IR", "Incident Response"),
    ("IRC", "Internet Relay Chat"),
    ("IRP", "Incident Response Plan"),
    ("ISO", "International Standards Organization"),
    ("ISP", "Internet Service Provider"),
    ("ISSO", "Information Systems Security Officer"),
    ("IV", "Initialization Vector"),
    ("KDC", "Key Distribution Center"),
    ("KEK", "Key Encryption Key"),
    ("L2TP", "Layer 2 Tunneling Protocol"),
    ("LAN", "Local Area Network"),
    ("LDAP", "Lightweight Directory Access Protocol"),
    ("LEAP", "Lightweight Extensible Authentication Protocol"),
    ("MaaS", "Monitoring as a Service"),
    ("MAC Ctrl", "Mandatory Access Control"),
    ("MAC Hw", "Media Access Control"),
    ("MAC", "Message Authentication Code"),
    ("MAN", "Metropolitan Area Network"),
    ("MBR", "Master Boot Record"),
    ("MD5", "Message Digest 5"),
    ("MDF", "Main Distribution Frame"),
    ("MDM", "Mobile Device Management"),
    ("MFA", "Multifactor Authentication"),
    ("MFD", "Multifunction Device"),
    ("MFP", "Multifunction Printer"),
    ("ML", "Machine Learning"),
    ("MMS", "Multimedia Message Service"),
    ("MOA", "Memorandum of Agreement"),
    ("MOU", "Memorandum of Understanding"),
    ("MPLS", "Multi-protocol Label Switching"),
    ("MSA", "Master Service Agreement"),
    ("MSCHAP", "Microsoft Challenge Handshake Authentication Protocol"),
    ("MSP", "Managed Service Provider"),
    ("MSSP", "Managed Security Service Provider"),
    ("MTBF", "Mean Time Between Failures"),
    ("MTTF", "Mean Time to Failure"),
    ("MTTR", "Mean Time to Recover"),
    ("MTU", "Maximum Transmission Unit"),
    ("NAC", "Network Access Control"),
    ("NAT", "Network Address Translation"),
    ("NDA", "Non-disclosure Agreement"),
    ("NFC", "Near Field Communication"),
    ("NGFW", "Next-generation Firewall"),
    ("NIDS", "Network-based Intrusion Detection System"),
    ("NIPS", "Network-based Intrusion Prevention System"),
    ("NIST", "National Institute of Standards & Technology"),
    ("NTFS", "New Technology File System"),
    ("NTLM", "New Technology LAN Manager"),
    ("NTP", "Network Time Protocol"),
    ("OAUTH", "Open Authorization"),
    ("OCSP", "Online Certificate Status Protocol"),
    ("OID", "Object Identifier"),
    ("OS", "Operating System"),
    ("OSINT", "Open-source Intelligence"),
    ("OSPF", "Open Shortest Path First"),
    ("OT", "Operational Technology"),
    ("OTA", "Over the Air"),
    ("OVAL", "Open Vulnerability Assessment Language"),
    ("P12", "PKCS #12"),
    ("P2P", "Peer to Peer"),
    ("PaaS", "Platform as a Service"),
    ("PAC", "Proxy Auto Configuration"),
    ("PAM Acc", "Privileged Access Management"),
    ("PAM", "Pluggable Authentication Modules"),
    ("PAP", "Password Authentication Protocol"),
    ("PAT", "Port Address Translation"),
    ("PBKDF2", "Password-based Key Derivation Function 2"),
    ("PBX", "Private Branch Exchange"),
    ("PCAP", "Packet Capture"),
    ("PCI DSS", "Payment Card Industry Data Security Standard"),
    ("PDU", "Power Distribution Unit"),
    ("PEAP", "Protected Extensible Authentication Protocol"),
    ("PED", "Personal Electronic Device"),
    ("PEM", "Privacy Enhanced Mail"),
    ("PFS", "Perfect Forward Secrecy"),
    ("PGP", "Pretty Good Privacy"),
    ("PHI", "Personal Health Information"),
    ("PII", "Personally Identifiable Information"),
    ("PIV", "Personal Identity Verification"),
    ("PKCS", "Public Key Cryptography Standards"),
    ("PKI", "Public Key Infrastructure"),
    ("POP", "Post Office Protocol"),
    ("POTS", "Plain Old Telephone Service"),
    ("PPP", "Point-to-Point Protocol"),
    ("PPTP", "Point-to-Point Tunneling Protocol"),
    ("PSK", "Pre-shared Key"),
    ("PTZ", "Pan-tilt-zoom"),
    ("PUP", "Potentially Unwanted Program"),
    ("RA", "Recovery Agent"),
    ("RA Auth", "Registration Authority"),
    ("RACE", "Research and Development in Advanced Communications Technologies in Europe"),
    ("RAD", "Rapid Application Development"),
    ("RADIUS", "Remote Authentication Dial-in User Service"),
    ("RAID", "Redundant Array of Inexpensive Disks"),
    ("RAS", "Remote Access Server"),
    ("RAT", "Remote Access Trojan"),
    ("RBAC ro", "Role-based Access Control"),
    ("RBAC", "Rule-based Access Control"),
    ("RC4", "Rivest Cipher version 4"),
    ("RDP", "Remote Desktop Protocol"),
    ("RFID", "Radio Frequency Identifier"),
    ("RIPEMD", "RACE Integrity Primitives Evaluation Message Digest"),
    ("ROI", "Return on Investment"),
    ("RPO", "Recovery Point Objective"),
    ("RSA", "Rivest, Shamir, & Adleman"),
    ("RTBH", "Remotely Triggered Black Hole"),
    ("RTO", "Recovery Time Objective"),
    ("RTOS", "Real-time Operating System"),
    ("RTP", "Real-time Transport Protocol"),
    ("S/MIME", "Secure/Multipurpose Internet Mail Extensions"),
    ("SaaS", "Software as a Service"),
    ("SAE", "Simultaneous Authentication of Equals"),
    ("SAML", "Security Assertions Markup Language"),
    ("SAN Hw", "Storage Area Network"),
    ("SAN", "Subject Alternative Name"),
    ("SASE", "Secure Access Service Edge"),
    ("SCADA", "Supervisory Control and Data Acquisition"),
    ("SCAP", "Security Content Automation Protocol"),
    ("SCEP", "Simple Certificate Enrollment Protocol"),
    ("SD-WAN", "Software-defined Wide Area Network"),
    ("SDK", "Software Development Kit"),
    ("SDLC", "Software Development Lifecycle"),
    ("SDLM", "Software Development Lifecycle Methodology"),
    ("SDN", "Software-defined Networking"),
    ("SE Linux", "Security-enhanced Linux"),
    ("SED", "Self-encrypting Drives"),
    ("SEH", "Structured Exception Handler"),
    ("SFTP", "Secured File Transfer Protocol"),
    ("SHA", "Secure Hashing Algorithm"),
    ("SHTTP", "Secure Hypertext Transfer Protocol"),
    ("SIEM", "Security Information and Event Management"),
    ("SIM", "Subscriber Identity Module"),
    ("SLA", "Service-level Agreement"),
    ("SLE", "Single Loss Expectancy"),
    ("SMS", "Short Message Service"),
    ("SMTP", "Simple Mail Transfer Protocol"),
    ("SMTPS", "Simple Mail Transfer Protocol Secure"),
    ("SNMP", "Simple Network Management Protocol"),
    ("SOAP", "Simple Object Access Protocol"),
    ("SOAR", "Security Orchestration, Automation, Response"),
    ("SoC", "System on Chip"),
    ("SOC", "Security Operations Center"),
    ("SOW", "Statement of Work"),
    ("SPF", "Sender Policy Framework"),
    ("SPIM", "Spam over Internet Messaging"),
    ("SQL", "Structured Query Language"),
    ("SQLi", "SQL Injection"),
    ("SRTP", "Secure Real-Time Protocol"),
    ("SSD", "Solid State Drive"),
    ("SSH", "Secure Shell"),
    ("SSL", "Secure Sockets Layer"),
    ("SSO", "Single Sign-on"),
    ("STIX", "Structured Threat Information eXchange"),
    ("SWG", "Secure Web Gateway"),
    ("TACACS+", "Terminal Access Controller Access Control System"),
    ("TAXII", "Trusted Automated eXchange of Indicator Information"),
    ("TCP/IP", "Transmission Control Protocol/Internet Protocol"),
    ("TGT", "Ticket Granting Ticket"),
    ("TKIP", "Temporal Key Integrity Protocol"),
    ("TLS", "Transport Layer Security"),
    ("TOC", "Time-of-check"),
    ("TOTP", "Time-based One-time Password"),
    ("TOU", "Time-of-use"),
    ("TPM", "Trusted Platform Module"),
    ("TTP", "Tactics, Techniques, and Procedures"),
    ("TSIG", "Transaction Signature"),
    ("UAT", "User Acceptance Testing"),
    ("UAV", "Unmanned Aerial Vehicle"),
    ("UDP", "User Datagram Protocol"),
    ("UEFI", "Unified Extensible Firmware Interface"),
    ("UEM", "Unified Endpoint Management"),
    ("UPS", "Uninterruptable Power Supply"),
    ("URI", "Uniform Resource Identifier"),
    ("URL", "Universal Resource Locator"),
    ("USB Classic", "Universal Serial Bus"),
    ("USB", "OTG USB On the Go"),
    ("UTM", "Unified Threat Management"),
    ("UTP", "Unshielded Twisted Pair"),
    ("VBA", "Visual Basic"),
    ("VDE", "Virtual Desktop Environment"),
    ("VDI", "Virtual Desktop Infrastructure"),
    ("VLAN", "Virtual Local Area Network"),
    ("VLSM", "Variable Length Subnet Masking"),
    ("VM", "Virtual Machine"),
    ("VoIP", "Voice over IP"),
    ("VPC", "Virtual Private Cloud"),
    ("VPN", "Virtual Private Network"),
    ("VTC", "Video Teleconferencing"),
    ("WAF", "Web Application Firewall"),
    ("WAP", "Wireless Access Point"),
    ("WEP", "Wired Equivalent Privacy"),
    ("WIDS", "Wireless Intrusion Detection System"),
    ("WIPS", "Wireless Intrusion Prevention System"),
    ("WO", "Work Order"),
    ("WPA", "Wi-Fi Protected Access"),
    ("WPS", "Wi-Fi Protected Setup"),
    ("WTLS", "Wireless TLS"),
    ("XDR", "Extended Detection and Response"),
    ("XML", "Extensible Markup Language"),
    ("XOR", "Exclusive Or"),
    ("XSRF", "Cross-site Request Forgery"),
    ("XSS", "Cross-site Scripting")
]

# Handle duplicates: allow multiple meanings
from collections import defaultdict
acronyms = defaultdict(list)
for key, value in acronym_list:
    acronyms[key].append(value)

# GUI Application
class AcronymQuizApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Acronym Quiz")
        self.root.geometry("500x400")

        # Variables for current state
        self.current_acronym = None
        self.answer_var = StringVar()
        self.score = ctk.IntVar(value=0)
        self.correct_count = ctk.IntVar(value=0)
        self.wrong_count = ctk.IntVar(value=0)

        # Widgets
        self.title_label = ctk.CTkLabel(root, text="Acronym Quiz Game", font=("Arial", 18, "bold"), text_color="blue")
        self.title_label.pack(pady=10)

        self.score_label = ctk.CTkLabel(root, text="Score: 0 (Correct: 0, Wrong: 0)", font=("Arial", 14))
        self.score_label.pack(pady=10)

        self.question_label = ctk.CTkLabel(root, text="Press 'Next' to start the quiz!", font=("Arial", 14), wraplength=400)
        self.question_label.pack(pady=20)

        self.answer_entry = ctk.CTkEntry(root, textvariable=self.answer_var, font=("Arial", 14), width=300)
        self.answer_entry.pack(pady=10)

        self.check_button = ctk.CTkButton(root, text="Check Answer", command=self.check_answer, fg_color="green", text_color="white")
        self.check_button.pack(pady=5)

        self.next_button = ctk.CTkButton(root, text="Next", command=self.next_question, fg_color="blue", text_color="white")
        self.next_button.pack(pady=5)

        self.exit_button = ctk.CTkButton(root, text="Exit", command=root.quit, fg_color="red", text_color="white")
        self.exit_button.pack(pady=5)

    def update_score(self):
        """Update the score on the UI."""
        self.score_label.configure(
            text=f"Score: {self.score.get()} (Correct: {self.correct_count.get()}, Wrong: {self.wrong_count.get()})"
        )

    def next_question(self):
        """Generate a new question."""
        self.current_acronym, meanings = random.choice(list(acronyms.items()))
        self.question_label.configure(text=f"What does the acronym '{self.current_acronym}' stand for?")
        self.answer_var.set("")  # Clear the entry box

    def check_answer(self):
        """Check the user's answer."""
        user_answer = self.answer_var.get().strip()
        correct_meanings = acronyms[self.current_acronym]

        if user_answer.lower() in [meaning.lower() for meaning in correct_meanings]:
            messagebox.showinfo("Result", "Correct! 🎉")
            self.score.set(self.score.get() + 1)  # Increment score
            self.correct_count.set(self.correct_count.get() + 1)  # Increment correct count
        else:
            messagebox.showerror("Result", f"Incorrect! The correct answers are:\n{', '.join(correct_meanings)}")
            self.wrong_count.set(self.wrong_count.get() + 1)  # Increment wrong count

        self.update_score()

# Main application loop
if __name__ == "__main__":
    ctk.set_appearance_mode("System")  # Modes: "System", "Light", "Dark"
    ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

    root = ctk.CTk()
    app = AcronymQuizApp(root)
    root.mainloop()
