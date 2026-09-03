export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at?: string;
  last_login_at?: string | null;
}

export type EventStatus = 'NORMAL' | 'SUSPICIOUS' | 'BLOCKED' | 'FLAGGED';

export interface NetworkEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  protocol: string;
  connection_state?: string;
  status: EventStatus;
  risk_score: number;
  process_name?: string;
  hostname?: string;
  payload_summary?: string;
  collector?: string;
  source?: string;
}

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'RESOLVED' | 'CLOSED';

export interface SecurityAlert {
  id: number;
  timestamp: string;
  updated_at?: string;
  detection_id?: number;
  detection_type: string;
  severity: AlertSeverity;
  confidence: number;
  risk_score?: number;
  source_ip: string;
  dest_ip: string;
  dest_port?: number;
  protocol?: string;
  description: string;
  explanation: string;
  status: AlertStatus;
  assigned_analyst: string;
  rule_id?: string;
  resolution?: string;
  resolution_reason?: string;
}

export type InvestigationStatus = 'OPEN' | 'IN_PROGRESS' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export interface AnalystNote {
  id: number;
  timestamp: string;
  author: string;
  note_text: string;
}

export interface Investigation {
  id: number;
  alert_id?: number;
  case_number: string;
  title: string;
  summary: string;
  source_ip: string;
  dest_ip: string;
  severity: AlertSeverity;
  status: InvestigationStatus;
  assigned_analyst: string;
  verdict?: string;
  verdict_reason?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  notes: AnalystNote[];
}

export interface DetectionRule {
  id: number;
  rule_code: string;
  name: string;
  description: string;
  severity: AlertSeverity;
  enabled: boolean;
  mitre_tactic?: string;
  mitre_technique?: string;
  condition_logic?: string;
  created_at?: string;
}

export interface Asset {
  id: number;
  hostname: string;
  ip_address: string;
  os?: string;
  role?: string;
  criticality?: string;
  last_seen?: string;
}

export interface SocStatistics {
  total_events: number;
  active_connections: number;
  suspicious_events: number;
  open_alerts: number;
  open_investigations?: number;
  total_detections?: number;
  monitored_assets?: number;
  protocol_distribution: { name: string; value: number }[];
  top_ports: { port: number; count: number }[];
}
