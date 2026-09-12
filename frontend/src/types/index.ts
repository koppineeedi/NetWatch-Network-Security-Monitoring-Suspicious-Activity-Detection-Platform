export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at?: string;
}

export interface NetworkEvent {
  id: number;
  timestamp: string;
  source: string;
  collector: string;
  event_type: string;
  source_ip?: string;
  source_port?: number;
  dest_ip?: string;
  dest_port?: number;
  protocol?: string;
  connection_state?: string;
  status: string;
  risk_score: number;
  process_name?: string;
  hostname?: string;
  bytes_sent?: number;
  bytes_received?: number;
  payload_summary?: string;
}

export interface SecurityAlert {
  id: number;
  timestamp: string;
  detection_id?: number;
  detection_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  risk_score: number;
  source_ip?: string;
  dest_ip?: string;
  dest_port?: number;
  protocol?: string;
  description: string;
  explanation?: string;
  status: 'NEW' | 'INVESTIGATING' | 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'RESOLVED' | 'CLOSED';
  assigned_analyst?: string;
  rule_id?: string;
}

export interface Detection {
  id: number;
  timestamp: string;
  rule_code: string;
  rule_name: string;
  source_ip?: string;
  target_ip?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  action_taken: string;
  details?: string;
  evidence?: string;
  risk_score: number;
}

export interface DetectionRule {
  id: number;
  rule_code: string;
  name: string;
  category: string;
  condition_desc: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  threshold: number;
  time_window: number;
  enabled: boolean;
}

export interface Asset {
  id: number;
  ip_address: string;
  hostname?: string;
  asset_type?: string;
  mac_address?: string;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  alerts_count: number;
  tags?: string;
}

export interface Investigation {
  id: number;
  case_number: string;
  alert_id: number;
  title: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED';
  assigned_analyst?: string;
  verdict?: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'BENIGN_ANOMALY' | 'INCONCLUSIVE';
  verdict_reason?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

export interface InvestigationNote {
  id: number;
  investigation_id: number;
  author: string;
  note: string;
  created_at: string;
}

export interface TimelineEvent {
  id: number;
  investigation_id: number;
  timestamp: string;
  title: string;
  description?: string;
  event_type: string;
}

export interface SocStatistics {
  total_events: number;
  active_connections: number;
  total_detections: number;
  open_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  investigations_open: number;
  total_assets: number;
}

// Enterprise Cycle 1 Interfaces
export interface Connector {
  id: number;
  connector_id: string;
  name: string;
  connector_type: string;
  status: 'DISABLED' | 'CONFIGURED' | 'CONNECTED' | 'ERROR' | 'NOT_CONFIGURED';
  config?: Record<string, any>;
  last_seen?: string;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface ConnectorTestResult {
  connector_id: string;
  status: string;
  message: string;
  details?: Record<string, any>;
}

export interface IOC {
  id: number;
  ioc_value: string;
  normalized_value: string;
  ioc_type: 'IP' | 'DOMAIN' | 'URL' | 'HASH_MD5' | 'HASH_SHA1' | 'HASH_SHA256' | 'EMAIL';
  source: string;
  confidence: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  first_seen?: string;
  last_seen?: string;
  expiration?: string;
  tags?: string;
  created_at: string;
  updated_at: string;
}

export interface IOCMatch {
  id: number;
  event_id?: number;
  alert_id?: number;
  ioc_id: number;
  ioc_value: string;
  ioc_type: string;
  matched_field: string;
  provider: string;
  confidence: number;
  severity: string;
  tags?: string;
  timestamp: string;
}

export interface IPReputation {
  ip_address: string;
  reputation_score: number;
  abuse_confidence: number;
  country?: string;
  asn?: string;
  organization?: string;
  isp?: string;
  categories?: string;
  provider: string;
  status: string;
  last_error?: string;
  lookup_timestamp: string;
}

export interface IPGeolocation {
  ip_address: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: string;
  organization?: string;
  provider: string;
  status: string;
}

export interface ThreatIntelProviderStatus {
  provider_name: string;
  display_name: string;
  status: string;
  enabled: boolean;
  ioc_count: number;
  last_sync?: string;
  last_error?: string;
}

export interface ThreatIntelStats {
  total_iocs: number;
  active_iocs: number;
  expired_iocs: number;
  providers: ThreatIntelProviderStatus[];
  recent_matches_count: number;
  high_confidence_matches_count: number;
  recent_matches: Array<{
    id: number;
    ioc_value: string;
    ioc_type: string;
    matched_field: string;
    provider: string;
    confidence: number;
    severity: string;
    timestamp: string;
  }>;
}

// Enterprise Cycle 2 Interfaces
export interface UEBAStatus {
  enabled: boolean;
  baseline_window_hours: number;
  min_events_threshold: number;
  refresh_minutes: number;
  risk_decay_hours: number;
  monitored_entities_count: number;
  active_baselines_count: number;
  insufficient_data_entities_count: number;
}

export interface AnalyticsStats {
  total_entities: number;
  entities_with_anomalies: number;
  high_risk_entities: number;
  critical_entities: number;
  active_campaigns: number;
  total_anomalies: number;
  baseline_status_breakdown: Record<string, number>;
}

export interface BehaviorBaseline {
  id: number;
  entity_type: string;
  entity_id: string;
  feature_name: string;
  mean_value: number;
  standard_deviation: number;
  median_value: number;
  percentile_95: number;
  minimum_value: number;
  maximum_value: number;
  sample_count: number;
  baseline_window_start?: string;
  baseline_window_end?: string;
  last_updated?: string;
  status: string;
}

export interface Entity {
  id: number;
  entity_id: string;
  entity_type: string;
  first_seen?: string;
  last_seen?: string;
  event_count: number;
  current_risk_score: number;
  baseline_status: 'ACTIVE' | 'INSUFFICIENT_DATA' | 'STALE';
  anomaly_count: number;
  high_risk_count: number;
  updated_at?: string;
}

export interface EntityRiskHistory {
  id: number;
  entity_type: string;
  entity_id: string;
  previous_score: number;
  new_score: number;
  contributing_factor?: string;
  evidence_id?: string;
  created_at: string;
}

export interface Anomaly {
  id: number;
  entity_type: string;
  entity_id: string;
  feature: string;
  observed_value: number;
  baseline_value: number;
  deviation: number;
  anomaly_score: number;
  confidence: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  explanation: string;
  evidence?: string;
  mitre_technique?: string;
  timestamp: string;
}

export interface Campaign {
  id: number;
  campaign_id: string;
  name: string;
  status: 'ACTIVE' | 'MONITORING' | 'RESOLVED' | 'CLOSED';
  risk_score: number;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  event_count: number;
  entity_count: number;
  technique_count: number;
  created_at: string;
  updated_at: string;
}

export interface CampaignEventDetails {
  campaign_id: string;
  alerts_count: number;
  anomalies_count: number;
  alerts: Array<{
    id: number;
    detection_type: string;
    severity: string;
    risk_score: number;
    source_ip?: string;
    dest_ip?: string;
    description: string;
    timestamp?: string;
  }>;
  anomalies: Array<{
    id: number;
    entity_id: string;
    feature: string;
    severity: string;
    anomaly_score: number;
    explanation: string;
    timestamp?: string;
  }>;
}

// Enterprise Cycle 3 Sigma Interfaces
export interface SigmaRule {
  id: number;
  rule_id: string;
  title: string;
  description?: string;
  status: 'DRAFT' | 'VALIDATED' | 'ENABLED' | 'DISABLED' | 'ERROR' | 'UNSUPPORTED';
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  author?: string;
  date?: string;
  modified?: string;
  logsource?: Record<string, any>;
  tags?: string[];
  references?: string[];
  falsepositives?: string[];
  enabled: boolean;
  version: number;
  raw_yaml: string;
  created_at: string;
  updated_at: string;
}

export interface SigmaValidationResult {
  valid: boolean;
  status: string;
  errors: string[];
  warnings: string[];
  unsupported_features: string[];
  rule_id?: string;
  title?: string;
}

export interface SigmaFieldMapping {
  sigma_field: string;
  netwatch_field?: string;
  supported: boolean;
  description?: string;
}

export interface SigmaSandboxResult {
  status: 'SUCCESS' | 'INSUFFICIENT_DATA' | 'ERROR';
  rule_id?: string;
  rule_title?: string;
  valid: boolean;
  mapped_fields_count: number;
  unsupported_fields: string[];
  historical_matches_count: number;
  events_evaluated?: number;
  execution_time_ms: number;
  matches: Array<{
    event_id: number;
    timestamp?: string;
    source?: string;
    source_ip?: string;
    dest_ip?: string;
    dest_port?: number;
    matched_fields: Array<{
      sigma_field: string;
      netwatch_field: string;
      observed: any;
      expected: any;
    }>;
    explanation: string;
    severity: string;
    mitre_techniques?: string[];
  }>;
  warnings: string[];
}

export interface SigmaStatistics {
  total_rules: number;
  enabled_rules: number;
  valid_rules: number;
  invalid_rules: number;
  total_executions: number;
  total_matches: number;
  average_execution_ms: number;
}

// Enterprise Cycle 4 SOAR Interfaces
export interface PlaybookStep {
  step_id: string;
  action: string;
  target?: string;
  parameters?: Record<string, any>;
  conditions?: Record<string, any>;
  timeout?: number;
  retry_count?: number;
  continue_on_failure?: boolean;
}

export interface SoarPlaybook {
  id: number;
  playbook_id: string;
  name: string;
  description?: string;
  enabled: boolean;
  version: number;
  trigger_type: string;
  trigger_config?: Record<string, any>;
  approval_policy: string;
  steps: PlaybookStep[];
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface SoarAction {
  id: number;
  action_id: string;
  action_type: string;
  status: 'PENDING_APPROVAL' | 'APPROVED' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'DENIED' | 'CANCELLED' | 'DRY_RUN' | 'NOT_CONFIGURED';
  alert_id?: number;
  case_id?: string;
  playbook_id?: string;
  requested_by: string;
  approved_by?: string;
  target: string;
  parameters?: Record<string, any>;
  result?: Record<string, any>;
  error?: string;
  started_at?: string;
  completed_at?: string;
  rollback_available: boolean;
  rollback_status: string;
  idempotency_key?: string;
  created_at: string;
}

export interface SoarApproval {
  id: number;
  approval_id: string;
  action_id: string;
  required_role: string;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'CANCELLED';
  requested_by: string;
  decided_by?: string;
  decision_reason?: string;
  created_at: string;
  expires_at?: string;
}

export interface SoarStatistics {
  total_playbooks: number;
  enabled_playbooks: number;
  total_actions: number;
  pending_approvals: number;
  successful_actions: number;
  failed_actions: number;
  dry_run_actions: number;
  not_configured_actions: number;
  integrations_status: Record<string, string>;
}


