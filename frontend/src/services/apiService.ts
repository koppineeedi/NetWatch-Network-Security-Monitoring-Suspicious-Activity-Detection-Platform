import {
  NetworkEvent, SecurityAlert, Investigation, DetectionRule, Asset, SocStatistics, User,
  Connector, ConnectorTestResult, IOC, IOCMatch, IPReputation, IPGeolocation, ThreatIntelStats, ThreatIntelProviderStatus,
  UEBAStatus, AnalyticsStats, BehaviorBaseline, Entity, EntityRiskHistory, Anomaly, Campaign, CampaignEventDetails
} from '../types';

const getBaseUrl = () => {
  if (typeof window !== 'undefined') {
    const host = window.location.hostname || '127.0.0.1';
    return `${window.location.protocol}//${host}:8000`;
  }
  return 'http://127.0.0.1:8000';
};

const BASE_URL = getBaseUrl();

export interface TelemetryStatus {
  running: boolean;
  collector: string;
  interval: number;
  last_collection_time: string | null;
  events_collected: number;
  events_stored: number;
  errors: number;
}

export interface LogIngestionRecord {
  id: number;
  ingestion_id: string;
  filename: string;
  file_type: string;
  file_size_bytes: number;
  source: string;
  timestamp: string;
  status: string;
  records_received: number;
  records_stored: number;
  records_rejected: number;
  records_duplicate: number;
}

export interface DetectionRecord {
  id: number;
  timestamp: string;
  rule_code: string;
  rule_name: string;
  source_ip: string | null;
  target_ip: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  action_taken: string;
  details: string | null;
  evidence: string | null;
  risk_score: number;
}

export interface TimelineEntry {
  timestamp: string;
  event_type: string;
  actor: string;
  title: string;
  details: string;
}

// Token helper
const getAuthHeaders = (): HeadersInit => {
  const token = localStorage.getItem('netwatch_token');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
};

const handleResponse = async (res: Response) => {
  if (res.status === 401) {
    localStorage.removeItem('netwatch_token');
    localStorage.removeItem('netwatch_user');
    window.dispatchEvent(new Event('netwatch_auth_expired'));
    throw new Error("Authentication token expired. Please log in again.");
  }
  if (res.status === 403) {
    const errData = await res.json().catch(() => ({ detail: "Access Forbidden" }));
    throw new Error(errData.detail || "Forbidden: You do not have permission for this action.");
  }
  if (!res.ok) {
    const errData = await res.json().catch(() => ({ detail: `HTTP Error ${res.status}` }));
    throw new Error(errData.detail || `Request failed with status ${res.status}`);
  }
  return await res.json();
};

export const apiService = {
  // Auth
  login: async (identifier: string, password: string): Promise<{ access_token: string; token_type: string; user: User }> => {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: identifier, password }),
      signal: AbortSignal.timeout(10000)
    });
    if (res.ok) {
      const data = await res.json();
      localStorage.setItem('netwatch_token', data.access_token);
      localStorage.setItem('netwatch_user', JSON.stringify(data.user));
      return data;
    }
    const err = await res.json().catch(() => ({ detail: "Invalid credentials" }));
    throw new Error(err.detail || "Invalid credentials");
  },

  logout: async () => {
    try {
      await fetch(`${BASE_URL}/api/auth/logout`, {
        method: 'POST',
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
    } catch {}
    localStorage.removeItem('netwatch_token');
    localStorage.removeItem('netwatch_user');
  },

  getMe: async (): Promise<User> => {
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  changePassword: async (currentPassword: string, newPassword: string) => {
    const res = await fetch(`${BASE_URL}/api/auth/change-password`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  // User Management (ADMIN)
  getUsers: async (): Promise<User[]> => {
    const res = await fetch(`${BASE_URL}/api/users`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  createUser: async (userData: { username: string; email: string; password: string; role?: string }): Promise<User> => {
    const res = await fetch(`${BASE_URL}/api/users`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(userData),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  updateUserRole: async (userId: number, role: string): Promise<User> => {
    const res = await fetch(`${BASE_URL}/api/users/${userId}/role`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ role }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  updateUserStatus: async (userId: number, isActive: boolean): Promise<User> => {
    const res = await fetch(`${BASE_URL}/api/users/${userId}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ is_active: isActive }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Health
  getHealth: async () => {
    const res = await fetch(`${BASE_URL}/api/health`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) throw new Error("Backend offline");
    return await res.json();
  },

  // Telemetry Controls
  getTelemetryStatus: async (): Promise<TelemetryStatus> => {
    try {
      const res = await fetch(`${BASE_URL}/api/telemetry/status`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return {
      running: false,
      collector: "LOCAL_NETWORK",
      interval: 10,
      last_collection_time: null,
      events_collected: 0,
      events_stored: 0,
      errors: 0
    };
  },

  startTelemetry: async (): Promise<TelemetryStatus> => {
    const res = await fetch(`${BASE_URL}/api/telemetry/start`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  stopTelemetry: async (): Promise<TelemetryStatus> => {
    const res = await fetch(`${BASE_URL}/api/telemetry/stop`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Detections
  getDetections: async (): Promise<DetectionRecord[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/detections`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  getDetectionById: async (id: number): Promise<DetectionRecord> => {
    const res = await fetch(`${BASE_URL}/api/detections/${id}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  evaluateDetections: async (): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/detections/evaluate`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Alerts
  getAlerts: async (status?: string, severity?: string, source_ip?: string): Promise<SecurityAlert[]> => {
    try {
      const params = new URLSearchParams();
      if (status) params.append('status', status);
      if (severity) params.append('severity', severity);
      if (source_ip) params.append('source_ip', source_ip);
      const res = await fetch(`${BASE_URL}/api/alerts?${params.toString()}`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  getAlertById: async (id: number): Promise<SecurityAlert> => {
    const res = await fetch(`${BASE_URL}/api/alerts/${id}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  updateAlertStatus: async (
    id: number,
    status?: string,
    assigned_analyst?: string,
    resolution?: string,
    resolution_reason?: string
  ): Promise<SecurityAlert> => {
    const res = await fetch(`${BASE_URL}/api/alerts/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, assigned_analyst, resolution, resolution_reason }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getAlertEvidenceEvents: async (alertId: number): Promise<NetworkEvent[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/alerts/${alertId}/events`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  getAlertThreatIntel: async (alertId: number): Promise<{ matched: boolean; match?: any }> => {
    try {
      const res = await fetch(`${BASE_URL}/api/alerts/${alertId}/threat-intel`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return { matched: false };
  },

  // Investigations
  getInvestigations: async (): Promise<Investigation[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/investigations`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  getInvestigationById: async (id: number): Promise<Investigation> => {
    const res = await fetch(`${BASE_URL}/api/investigations/${id}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  createInvestigationFromAlert: async (alertId: number): Promise<Investigation> => {
    const res = await fetch(`${BASE_URL}/api/investigations`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ alert_id: alertId }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  updateInvestigation: async (
    id: number,
    status?: string,
    verdict?: string,
    verdict_reason?: string
  ): Promise<Investigation> => {
    const res = await fetch(`${BASE_URL}/api/investigations/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, verdict, verdict_reason }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  addAnalystNote: async (invId: number, note_text: string) => {
    const res = await fetch(`${BASE_URL}/api/investigations/${invId}/notes`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ note_text }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getInvestigationTimeline: async (invId: number): Promise<TimelineEntry[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/investigations/${invId}/timeline`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  // IP Analysis
  getIPAnalysis: async (ip: string): Promise<any> => {
    try {
      const res = await fetch(`${BASE_URL}/api/ip/${ip}`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  },

  // Log Upload & History
  uploadLogFile: async (file: File): Promise<LogIngestionRecord> => {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('netwatch_token');
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${BASE_URL}/api/logs/upload`, {
      method: 'POST',
      headers,
      body: formData
    });

    return await handleResponse(res);
  },

  getLogHistory: async (): Promise<LogIngestionRecord[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/logs`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  // Statistics
  getStatistics: async (): Promise<SocStatistics> => {
    try {
      const res = await fetch(`${BASE_URL}/api/statistics`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return {
      total_events: 0,
      active_connections: 0,
      total_detections: 0,
      open_alerts: 0,
      critical_alerts: 0,
      high_alerts: 0,
      medium_alerts: 0,
      low_alerts: 0,
      investigations_open: 0,
      total_assets: 0
    };
  },

  // Events
  getEvents: async (search?: string, protocol?: string, status?: string): Promise<NetworkEvent[]> => {
    try {
      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (protocol) params.append('protocol', protocol);
      if (status) params.append('status', status);

      const res = await fetch(`${BASE_URL}/api/events?${params.toString()}`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  // Rules
  getRules: async (): Promise<DetectionRule[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/rules`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  toggleRule: async (id: number, enabled: boolean): Promise<DetectionRule> => {
    const res = await fetch(`${BASE_URL}/api/rules/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ enabled }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  createRule: async (rule: Partial<DetectionRule>): Promise<DetectionRule> => {
    const res = await fetch(`${BASE_URL}/api/rules`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(rule),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Assets
  getAssets: async (): Promise<Asset[]> => {
    try {
      const res = await fetch(`${BASE_URL}/api/assets`, {
        headers: getAuthHeaders(),
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) return await res.json();
    } catch {}
    return [];
  },

  // Enterprise Cycle 1: Connectors API
  getConnectors: async (): Promise<Connector[]> => {
    const res = await fetch(`${BASE_URL}/api/connectors`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  createConnector: async (data: { connector_id: string; name: string; connector_type: string; config?: any }): Promise<Connector> => {
    const res = await fetch(`${BASE_URL}/api/connectors`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  testConnector: async (id: string, config?: any): Promise<ConnectorTestResult> => {
    const res = await fetch(`${BASE_URL}/api/connectors/${id}/test`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(config || {}),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  enableConnector: async (id: string): Promise<Connector> => {
    const res = await fetch(`${BASE_URL}/api/connectors/${id}/enable`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  disableConnector: async (id: string): Promise<Connector> => {
    const res = await fetch(`${BASE_URL}/api/connectors/${id}/disable`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Enterprise Cycle 1: Threat Intelligence API
  getThreatIntelStatus: async (): Promise<ThreatIntelStats> => {
    const res = await fetch(`${BASE_URL}/api/threat-intelligence/status`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getTIProviders: async (): Promise<ThreatIntelProviderStatus[]> => {
    const res = await fetch(`${BASE_URL}/api/threat-intelligence/providers`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  testTIProvider: async (name: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/threat-intelligence/providers/${name}/test`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  getIOCs: async (search?: string, ioc_type?: string, source?: string, severity?: string): Promise<IOC[]> => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (ioc_type) params.append('ioc_type', ioc_type);
    if (source) params.append('source', source);
    if (severity) params.append('severity', severity);

    const res = await fetch(`${BASE_URL}/api/iocs?${params.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  createIOC: async (iocData: { ioc_value: string; ioc_type: string; source?: string; confidence?: number; severity?: string; tags?: string }): Promise<IOC> => {
    const res = await fetch(`${BASE_URL}/api/iocs`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(iocData),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  deleteIOC: async (id: number): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/iocs/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  uploadIOCFeed: async (file: File): Promise<any> => {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('netwatch_token');
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${BASE_URL}/api/iocs/upload`, {
      method: 'POST',
      headers,
      body: formData
    });
    return await handleResponse(res);
  },

  getIPReputation: async (ip: string): Promise<IPReputation> => {
    const res = await fetch(`${BASE_URL}/api/ip/${ip}/reputation`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getIPGeolocation: async (ip: string): Promise<IPGeolocation> => {
    const res = await fetch(`${BASE_URL}/api/ip/${ip}/geolocation`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Enterprise Cycle 2: UEBA & Behavioral Analytics
  getUEBAStatus: async (): Promise<UEBAStatus> => {
    const res = await fetch(`${BASE_URL}/api/ueba/status`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getAnalyticsStats: async (): Promise<AnalyticsStats> => {
    const res = await fetch(`${BASE_URL}/api/ueba/stats`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  triggerAnalyticsCycle: async (): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/ueba/trigger-cycle`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  getEntities: async (minRisk?: number, baselineStatus?: string, limit: number = 100): Promise<Entity[]> => {
    const params = new URLSearchParams();
    if (minRisk !== undefined) params.append('min_risk', minRisk.toString());
    if (baselineStatus) params.append('baseline_status', baselineStatus);
    params.append('limit', limit.toString());

    const res = await fetch(`${BASE_URL}/api/entities?${params.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getEntityById: async (entityId: string): Promise<Entity> => {
    const res = await fetch(`${BASE_URL}/api/entities/${entityId}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getEntityRiskHistory: async (entityId: string): Promise<EntityRiskHistory[]> => {
    const res = await fetch(`${BASE_URL}/api/entities/${entityId}/risk-history`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getEntityBaselines: async (entityId: string): Promise<BehaviorBaseline[]> => {
    const res = await fetch(`${BASE_URL}/api/entities/${entityId}/baselines`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getPeerGroupAnalysis: async (entityId: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/entities/${entityId}/peer-group`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getEntityAnomalies: async (entityId: string): Promise<Anomaly[]> => {
    const res = await fetch(`${BASE_URL}/api/entities/${entityId}/anomalies`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getAnomalies: async (severity?: string, entityId?: string, minScore?: number, limit: number = 100): Promise<Anomaly[]> => {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (entityId) params.append('entity_id', entityId);
    if (minScore !== undefined) params.append('min_score', minScore.toString());
    params.append('limit', limit.toString());

    const res = await fetch(`${BASE_URL}/api/anomalies?${params.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getAnomalyById: async (anomalyId: number): Promise<Anomaly> => {
    const res = await fetch(`${BASE_URL}/api/anomalies/${anomalyId}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getCampaigns: async (status?: string, limit: number = 50): Promise<Campaign[]> => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    params.append('limit', limit.toString());

    const res = await fetch(`${BASE_URL}/api/campaigns?${params.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getCampaignById: async (campaignId: string): Promise<Campaign> => {
    const res = await fetch(`${BASE_URL}/api/campaigns/${campaignId}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getCampaignEvents: async (campaignId: string): Promise<CampaignEventDetails> => {
    const res = await fetch(`${BASE_URL}/api/campaigns/${campaignId}/events`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  triggerCampaignClustering: async (): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/campaigns/trigger-cluster`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  // Enterprise Cycle 3: Sigma Engine & Sandbox API
  getSigmaRules: async (search?: string, status?: string, level?: string): Promise<SigmaRule[]> => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (status) params.append('status', status);
    if (level) params.append('level', level);

    const res = await fetch(`${BASE_URL}/api/sigma/rules?${params.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getSigmaRuleById: async (ruleId: string): Promise<SigmaRule> => {
    const res = await fetch(`${BASE_URL}/api/sigma/rules/${ruleId}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  importSigmaRules: async (raw_yaml: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/sigma/rules/import`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ raw_yaml }),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  enableSigmaRule: async (ruleId: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/sigma/rules/${ruleId}/enable`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  disableSigmaRule: async (ruleId: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/sigma/rules/${ruleId}/disable`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  deleteSigmaRule: async (ruleId: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/sigma/rules/${ruleId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  validateSigmaYaml: async (raw_yaml: string): Promise<SigmaValidationResult> => {
    const res = await fetch(`${BASE_URL}/api/sigma/validate`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ raw_yaml }),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  runSigmaSandbox: async (data: { raw_yaml?: string; rule_id?: string; hours?: number; log_source?: string }): Promise<SigmaSandboxResult> => {
    const res = await fetch(`${BASE_URL}/api/sigma/sandbox/test`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  getSigmaStatistics: async (): Promise<SigmaStatistics> => {
    const res = await fetch(`${BASE_URL}/api/sigma/statistics`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getSigmaFieldMappings: async (): Promise<SigmaFieldMapping[]> => {
    const res = await fetch(`${BASE_URL}/api/sigma/mappings`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // SOAR Subsystem Endpoints
  getSoarPlaybooks: async (): Promise<SoarPlaybook[]> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  createSoarPlaybook: async (data: any): Promise<SoarPlaybook> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  updateSoarPlaybook: async (playbook_id: string, data: any): Promise<SoarPlaybook> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks/${playbook_id}`, {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  deleteSoarPlaybook: async (playbook_id: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks/${playbook_id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  enableSoarPlaybook: async (playbook_id: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks/${playbook_id}/enable`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  disableSoarPlaybook: async (playbook_id: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks/${playbook_id}/disable`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  dryRunSoarPlaybook: async (playbook_id: string, context: any): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks/${playbook_id}/dry-run`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(context),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  executeSoarPlaybook: async (playbook_id: string, context: any): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/playbooks/${playbook_id}/execute`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(context),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  getSoarActions: async (status?: string, action_type?: string): Promise<SoarAction[]> => {
    let url = `${BASE_URL}/api/soar/actions?`;
    if (status) url += `status=${status}&`;
    if (action_type) url += `action_type=${action_type}&`;
    const res = await fetch(url, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  requestSoarAction: async (data: { action_type: string; target: str; alert_id?: number; case_id?: string; parameters?: any; dry_run?: boolean }): Promise<SoarAction> => {
    const res = await fetch(`${BASE_URL}/api/soar/actions`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  getSoarApprovals: async (status: string = 'PENDING'): Promise<SoarApproval[]> => {
    const res = await fetch(`${BASE_URL}/api/soar/approvals?status=${status}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  decideSoarApproval: async (approval_id: string, decision: string, reason?: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/approvals/${approval_id}/decide`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ decision, reason }),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  rollbackSoarAction: async (action_id: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/soar/actions/${action_id}/rollback`, {
      method: 'POST',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  getSoarIntegrations: async (): Promise<Record<string, string>> => {
    const res = await fetch(`${BASE_URL}/api/soar/integrations`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  getSoarStatistics: async (): Promise<SoarStatistics> => {
    const res = await fetch(`${BASE_URL}/api/soar/statistics`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  // Threat Hunting & SOC Upgrade Endpoints
  executeThreatHuntQuery: async (params: Record<string, any>): Promise<any> => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') query.append(k, String(v));
    });
    const res = await fetch(`${BASE_URL}/api/hunting/query?${query.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  getThreatHuntReports: async (): Promise<any[]> => {
    const res = await fetch(`${BASE_URL}/api/hunting/reports`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  createThreatHuntReport: async (payload: Record<string, any>): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/hunting/reports`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  getMitreCoverage: async (): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/mitre/coverage`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  replayDetectionRule: async (payload: Record<string, any>): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/detection/replay`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  },

  getInvestigationEvidence: async (investigationId: number): Promise<any[]> => {
    const res = await fetch(`${BASE_URL}/api/investigations/${investigationId}/evidence`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  attachInvestigationEvidence: async (investigationId: number, payload: Record<string, any>): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/investigations/${investigationId}/evidence`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  detachInvestigationEvidence: async (investigationId: number, evidenceId: number): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/investigations/${investigationId}/evidence/${evidenceId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  getAuditLogs: async (params?: Record<string, any>): Promise<any> => {
    const query = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') query.append(k, String(v));
      });
    }
    const res = await fetch(`${BASE_URL}/api/audit?${query.toString()}`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(3000)
    });
    return await handleResponse(res);
  },

  triggerDemoScenario: async (scenarioType: string): Promise<any> => {
    const res = await fetch(`${BASE_URL}/api/telemetry/demo-scenario`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ scenario_type: scenarioType }),
      signal: AbortSignal.timeout(5000)
    });
    return await handleResponse(res);
  }
};
