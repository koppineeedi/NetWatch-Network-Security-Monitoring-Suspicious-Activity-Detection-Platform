import { NetworkEvent, SecurityAlert, Investigation, DetectionRule, Asset, SocStatistics, TrainingScenario } from '../types';

export const initialMockEvents: NetworkEvent[] = [
  {
    id: 101,
    timestamp: new Date(Date.now() - 2 * 60000).toISOString(),
    source_ip: "192.168.1.45",
    dest_ip: "10.0.0.10",
    source_port: 54120,
    dest_port: 443,
    protocol: "HTTPS",
    packets: 24,
    bytes: 14200,
    status: "SUSPICIOUS",
    risk_score: 78.5,
    source_host: "ws-fin-23",
    dest_host: "web-prod-srv01",
    payload_summary: "POST /api/v1/checkout HTTP/1.1 | Host: web-prod-srv01 | User-Agent: CustomPython/3.10",
    collector: "ZEEK_NSM_AGENT_01"
  },
  {
    id: 102,
    timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
    source_ip: "192.168.1.45",
    dest_ip: "10.0.0.20",
    source_port: 54122,
    dest_port: 22,
    protocol: "TCP",
    packets: 48,
    bytes: 3820,
    status: "SUSPICIOUS",
    risk_score: 92.0,
    source_host: "ws-fin-23",
    dest_host: "db-master-01",
    payload_summary: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1 | Auth attempt root",
    collector: "ZEEK_NSM_AGENT_01"
  },
  {
    id: 103,
    timestamp: new Date(Date.now() - 12 * 60000).toISOString(),
    source_ip: "192.168.1.102",
    dest_ip: "8.8.8.8",
    source_port: 60112,
    dest_port: 53,
    protocol: "DNS",
    packets: 4,
    bytes: 320,
    status: "NORMAL",
    risk_score: 5.0,
    source_host: "ws-dev-02",
    dest_host: "dns-google-primary",
    payload_summary: "Standard query 0x1a2b A api.netwatch.io",
    collector: "SURICATA_IDS_01"
  },
  {
    id: 104,
    timestamp: new Date(Date.now() - 18 * 60000).toISOString(),
    source_ip: "10.0.0.10",
    dest_ip: "198.51.100.44",
    source_port: 44320,
    dest_port: 8080,
    protocol: "HTTP",
    packets: 180,
    bytes: 15400000,
    status: "FLAGGED",
    risk_score: 85.0,
    source_host: "web-prod-srv01",
    dest_host: "ext-remote-sync",
    payload_summary: "POST /backup/upload payload size 15.4MB enc=gzip",
    collector: "ZEEK_NSM_AGENT_01"
  },
  {
    id: 105,
    timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
    source_ip: "192.168.1.88",
    dest_ip: "10.0.0.5",
    source_port: 49200,
    dest_port: 3389,
    protocol: "TCP",
    packets: 12,
    bytes: 1240,
    status: "NORMAL",
    risk_score: 12.0,
    source_host: "ws-admin-01",
    dest_host: "dc-main-01",
    payload_summary: "Remote Desktop Protocol negotiation domain=NETWATCH user=admin",
    collector: "SURICATA_IDS_01"
  }
];

export const initialMockAlerts: SecurityAlert[] = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    detection_type: "Port Scanning Reconnaissance",
    severity: "HIGH",
    confidence: 0.92,
    source_ip: "192.168.1.45",
    dest_ip: "10.0.0.10",
    dest_port: 443,
    protocol: "TCP",
    description: "Internal workstation 192.168.1.45 executed multi-port probe against Web Server.",
    explanation: "Detected 24 distinct port probes in 30 seconds. Potential insider reconnaissance or compromised internal host.",
    status: "NEW",
    assigned_analyst: "Unassigned",
    rule_id: "R-SCAN-01"
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    detection_type: "SSH / RDP Credential Spraying",
    severity: "CRITICAL",
    confidence: 0.98,
    source_ip: "192.168.1.45",
    dest_ip: "10.0.0.20",
    dest_port: 22,
    protocol: "TCP",
    description: "Repeated SSH authentication attempts against Database Server.",
    explanation: "Over 40 rapid connection bursts within 20s targeting SSH port 22.",
    status: "INVESTIGATING",
    assigned_analyst: "Tier-1 Analyst",
    rule_id: "R-BRUTE-01"
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 120 * 60000).toISOString(),
    detection_type: "Large Outbound Data Exfiltration",
    severity: "HIGH",
    confidence: 0.88,
    source_ip: "10.0.0.10",
    dest_ip: "198.51.100.44",
    dest_port: 443,
    protocol: "HTTPS",
    description: "15.4 MB payload transferred to unknown external endpoint.",
    explanation: "Exceeded exfiltration volume baseline threshold by 154%.",
    status: "RESOLVED",
    assigned_analyst: "SOC Manager",
    rule_id: "R-EXFIL-01"
  }
];

export const initialMockInvestigations: Investigation[] = [
  {
    id: 1,
    alert_id: 2,
    case_number: "INC-2026-001",
    title: "Suspicious SSH Brute-Force from Finance Workstation",
    summary: "Workstation 192.168.1.45 flagged for high rate SSH authentication attempts against Database Server (10.0.0.20).",
    source_ip: "192.168.1.45",
    dest_ip: "10.0.0.20",
    severity: "CRITICAL",
    status: "IN_PROGRESS",
    assigned_analyst: "Tier-1 Analyst",
    created_at: new Date(Date.now() - 40 * 60000).toISOString(),
    updated_at: new Date(Date.now() - 10 * 60000).toISOString(),
    notes: [
      {
        id: 10,
        timestamp: new Date(Date.now() - 35 * 60000).toISOString(),
        author: "Tier-1 Analyst",
        note_text: "Initial triage: Workstation 192.168.1.45 belongs to user 'j.doe'. Reached out to user to confirm if script was running."
      },
      {
        id: 11,
        timestamp: new Date(Date.now() - 10 * 60000).toISOString(),
        author: "Tier-1 Analyst",
        note_text: "Host isolated via network ACL as precautionary measure pending malware scan."
      }
    ]
  }
];

export const initialMockRules: DetectionRule[] = [
  {
    id: 1,
    rule_code: "R-SCAN-01",
    name: "Port Scanning Reconnaissance",
    category: "RECONNAISSANCE",
    condition_desc: "Triggers when a host connects to >10 distinct target ports within 60s.",
    severity: "HIGH",
    threshold: 10,
    time_window: 60,
    enabled: true
  },
  {
    id: 2,
    rule_code: "R-BRUTE-01",
    name: "SSH / RDP Credential Spraying",
    category: "CREDENTIAL_ACCESS",
    condition_desc: "High packet count SSH/RDP connection attempts in short window.",
    severity: "CRITICAL",
    threshold: 15,
    time_window: 30,
    enabled: true
  },
  {
    id: 3,
    rule_code: "R-EXFIL-01",
    name: "Large Outbound Data Exfiltration",
    category: "EXFILTRATION",
    condition_desc: "Data transfer size exceeding 10MB in a single connection.",
    severity: "CRITICAL",
    threshold: 10000000,
    time_window: 120,
    enabled: true
  },
  {
    id: 4,
    rule_code: "R-ANOM-01",
    name: "DNS/ICMP Payload Anomaly",
    category: "COMMAND_AND_CONTROL",
    condition_desc: "Abnormal payload size on non-customary protocol channels.",
    severity: "MEDIUM",
    threshold: 5000,
    time_window: 60,
    enabled: true
  }
];

export const initialMockAssets: Asset[] = [
  {
    id: 1,
    hostname: "edge-fw-01",
    ip_address: "192.168.1.1",
    asset_type: "FIREWALL",
    status: "HEALTHY",
    risk_score: 10.0,
    risk_level: "LOW",
    events_count: 5400,
    alerts_count: 0,
    description: "Primary Perimeter Gateway Firewall"
  },
  {
    id: 2,
    hostname: "core-switch-01",
    ip_address: "192.168.1.2",
    asset_type: "CORE_SWITCH",
    status: "HEALTHY",
    risk_score: 15.0,
    risk_level: "LOW",
    events_count: 8200,
    alerts_count: 0,
    description: "Main Network Core Switch"
  },
  {
    id: 3,
    hostname: "web-prod-srv01",
    ip_address: "10.0.0.10",
    asset_type: "WEB_SERVER",
    status: "WARNING",
    risk_score: 58.0,
    risk_level: "HIGH",
    events_count: 1420,
    alerts_count: 3,
    description: "Public E-Commerce Nginx Web Server"
  },
  {
    id: 4,
    hostname: "db-master-01",
    ip_address: "10.0.0.20",
    asset_type: "DB_SERVER",
    status: "HEALTHY",
    risk_score: 22.0,
    risk_level: "LOW",
    events_count: 650,
    alerts_count: 1,
    description: "Primary PostgreSQL Relational Database"
  },
  {
    id: 5,
    hostname: "ws-fin-23",
    ip_address: "192.168.1.45",
    asset_type: "WORKSTATION",
    status: "CRITICAL",
    risk_score: 88.0,
    risk_level: "CRITICAL",
    events_count: 3200,
    alerts_count: 7,
    description: "Finance Dept Workstation (Flagged anomaly)"
  },
  {
    id: 6,
    hostname: "dc-main-01",
    ip_address: "10.0.0.5",
    asset_type: "DOMAIN_CONTROLLER",
    status: "HEALTHY",
    risk_score: 18.0,
    risk_level: "LOW",
    events_count: 2100,
    alerts_count: 0,
    description: "Active Directory Domain Controller"
  }
];

export const mockTrainingScenarios: TrainingScenario[] = [
  {
    id: "scen-01",
    title: "Scenario 1: Detecting TCP SYN Port Scanning",
    difficulty: "Beginner",
    category: "Reconnaissance",
    description: "Analyze raw firewall connection logs to identify a host executing rapid port probes across private internal IP subnet.",
    logs: [
      "2026-08-26 14:01:02 SRC=192.168.1.45 DST=10.0.0.10 DPT=21 PROTO=TCP SYN",
      "2026-08-26 14:01:03 SRC=192.168.1.45 DST=10.0.0.10 DPT=22 PROTO=TCP SYN",
      "2026-08-26 14:01:03 SRC=192.168.1.45 DST=10.0.0.10 DPT=80 PROTO=TCP SYN",
      "2026-08-26 14:01:04 SRC=192.168.1.45 DST=10.0.0.10 DPT=443 PROTO=TCP SYN",
      "2026-08-26 14:01:05 SRC=192.168.1.45 DST=10.0.0.10 DPT=3389 PROTO=TCP SYN"
    ],
    questions: [
      {
        id: 1,
        questionText: "Which IP address is the origin of the port scanning activity?",
        options: ["10.0.0.10", "192.168.1.45", "192.168.1.1", "127.0.0.1"],
        correctIndex: 1,
        explanation: "192.168.1.45 is listed as SRC across sequential connections to multiple destination ports.",
        defensiveHint: "Check the SRC (source) field in the log entries."
      },
      {
        id: 2,
        questionText: "What MITRE ATT&CK tactic does this activity map to?",
        options: ["TA0010 Exfiltration", "TA0043 Reconnaissance", "TA0006 Credential Access", "TA0011 Command & Control"],
        correctIndex: 1,
        explanation: "Network service port discovery maps to MITRE Reconnaissance (TA0043 / T1046).",
        defensiveHint: "Port scanning is used to gather information before launching targeted attacks."
      }
    ]
  },
  {
    id: "scen-02",
    title: "Scenario 2: SSH Brute-Force Authentication Attack",
    difficulty: "Intermediate",
    category: "Credential Access",
    description: "Review SSH server authentication log telemetry to spot password guessing bursts against administrative accounts.",
    logs: [
      "Aug 26 14:15:01 db-master-01 sshd[1420]: Failed password for invalid user admin from 192.168.1.45 port 51102 ssh2",
      "Aug 26 14:15:02 db-master-01 sshd[1422]: Failed password for root from 192.168.1.45 port 51104 ssh2",
      "Aug 26 14:15:02 db-master-01 sshd[1425]: Failed password for root from 192.168.1.45 port 51106 ssh2",
      "Aug 26 14:15:03 db-master-01 sshd[1428]: Failed password for postgres from 192.168.1.45 port 51108 ssh2"
    ],
    questions: [
      {
        id: 1,
        questionText: "What is the primary indicator of brute-force password guessing here?",
        options: [
          "DNS query resolution failures",
          "Rapid consecutive failed password attempts for privileged users",
          "Large HTTP file upload payload",
          "ICMP echo request flood"
        ],
        correctIndex: 1,
        explanation: "High frequency failed password logs for root/admin within seconds indicate dictionary or brute-force attack.",
        defensiveHint: "Look for repeated 'Failed password' entries in sshd logs."
      }
    ]
  },
  {
    id: "scen-03",
    title: "Scenario 3: Outbound Data Exfiltration Over HTTPS",
    difficulty: "Advanced",
    category: "Exfiltration",
    description: "Investigate suspicious data flow volume anomalies originating from internal web server to external unapproved IP.",
    logs: [
      "TIMESTAMP=2026-08-26T14:30:00 SRC=10.0.0.10 DST=198.51.100.44 BYTES=15428900 PROTO=HTTPS ACTION=ALLOWED"
    ],
    questions: [
      {
        id: 1,
        questionText: "Why is a 15.4MB outbound connection flagged as suspicious for host 10.0.0.10?",
        options: [
          "Because 10.0.0.10 is an internal host transferring excessive data volume to an external non-standard IP",
          "Because HTTPS protocol is inherently illegal",
          "Because port 443 is blocked by default",
          "Because packet size cannot exceed 100 bytes"
        ],
        correctIndex: 0,
        explanation: "15.4MB outbound payload significantly exceeds typical baseline threshold for web server outgoing requests.",
        defensiveHint: "Compare BYTES against normal operational baselines."
      }
    ]
  },
  {
    id: "scen-04",
    title: "Scenario 4: DNS Tunneling Anomaly",
    difficulty: "Intermediate",
    category: "Command & Control",
    description: "Examine DNS query telemetry containing long encoded subdomains used for data encapsulation.",
    logs: [
      "2026-08-26 14:40:10 SRC=192.168.1.45 QNAME=a3f910ba8201cd9912a.c2.attacker.net QTYPE=TXT BYTES=4096"
    ],
    questions: [
      {
        id: 1,
        questionText: "What feature in the DNS query points to DNS Tunneling?",
        options: [
          "High length entropy-encoded subdomain name and TXT query type with high byte count",
          "Standard google.com search query",
          "UDP port 53 usage",
          "Missing source IP"
        ],
        correctIndex: 0,
        explanation: "DNS Tunneling embeds data inside long base64/hex subdomains requesting TXT records.",
        defensiveHint: "Examine QNAME string length and complexity."
      }
    ]
  },
  {
    id: "scen-05",
    title: "Scenario 5: Web Shell Command Execution",
    difficulty: "Advanced",
    category: "Persistence",
    description: "Analyze web server access logs for HTTP GET requests containing system command parameter injection.",
    logs: [
      "192.168.1.45 - - [26/Aug/2026:14:50:00 +0000] \"GET /uploads/shell.php?cmd=whoami%20%26%26%20cat%20/etc/passwd HTTP/1.1\" 200 4500"
    ],
    questions: [
      {
        id: 1,
        questionText: "What URI parameter indicates web shell interaction?",
        options: [
          "/uploads/shell.php?cmd=whoami%20%26%26%20cat%20/etc/passwd",
          "HTTP/1.1 status 200",
          "Date header",
          "Port 80 HTTP protocol"
        ],
        correctIndex: 0,
        explanation: "`cmd=whoami && cat /etc/passwd` shows direct system command execution via an uploaded shell script.",
        defensiveHint: "Look for command invocation parameters like cmd= or exec= in query strings."
      }
    ]
  }
];
