import {
  NetworkEvent, SecurityAlert, Investigation, DetectionRule, Asset, SocStatistics, User
} from '../types';

const BASE_URL = 'http://127.0.0.1:8000';

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
      signal: AbortSignal.timeout(3000)
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
        signal: AbortSignal.timeout(2000)
      });
    } catch {}
    localStorage.removeItem('netwatch_token');
    localStorage.removeItem('netwatch_user');
  },

  getMe: async (): Promise<User> => {
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(2000)
    });
    return await handleResponse(res);
  },

  changePassword: async (currentPassword: string, newPassword: string) => {
    const res = await fetch(`${BASE_URL}/api/auth/change-password`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      signal: AbortSignal.timeout(2000)
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

  updateUserStatus: async (userId: number, isActive: bool): Promise<User> => {
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
      suspicious_events: 0,
      open_alerts: 0,
      open_investigations: 0,
      total_detections: 0,
      monitored_assets: 0,
      protocol_distribution: [],
      top_ports: []
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
  }
};
