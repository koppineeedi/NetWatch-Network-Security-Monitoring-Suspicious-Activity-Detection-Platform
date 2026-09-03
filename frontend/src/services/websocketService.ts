export type WsConnectionStatus = 'CONNECTED' | 'RECONNECTING' | 'OFFLINE';

export type WsMessageHandler = (data: any) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private status: WsConnectionStatus = 'OFFLINE';
  private listeners: Map<string, Set<WsMessageHandler>> = new Map();
  private statusListeners: Set<(status: WsConnectionStatus) => void> = new Set();

  private reconnectAttempts = 0;
  private maxReconnectDelay = 30000;
  private reconnectTimer: any = null;
  private pingInterval: any = null;
  private explicitDisconnect = false;

  public getStatus(): WsConnectionStatus {
    return this.status;
  }

  public onStatusChange(callback: (status: WsConnectionStatus) => void) {
    this.statusListeners.add(callback);
    callback(this.status);
    return () => {
      this.statusListeners.delete(callback);
    };
  }

  private setStatus(newStatus: WsConnectionStatus) {
    this.status = newStatus;
    this.statusListeners.forEach((cb) => cb(newStatus));
  }

  public connect() {
    const token = localStorage.getItem('netwatch_token');
    if (!token) {
      this.disconnect();
      return;
    }

    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.explicitDisconnect = false;
    this.setStatus('RECONNECTING');

    const wsUrl = `ws://127.0.0.1:8000/ws/events?token=${encodeURIComponent(token)}`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.setStatus('CONNECTED');
        this.startHeartbeat();
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload && payload.type) {
            const handlers = this.listeners.get(payload.type);
            if (handlers) {
              handlers.forEach((cb) => cb(payload.data || payload));
            }
          }
        } catch {}
      };

      this.ws.onclose = (event) => {
        this.stopHeartbeat();
        if (!this.explicitDisconnect) {
          this.setStatus('RECONNECTING');
          this.scheduleReconnect();
        } else {
          this.setStatus('OFFLINE');
        }
      };

      this.ws.onerror = () => {
        if (this.ws) {
          this.ws.close();
        }
      };
    } catch {
      this.setStatus('OFFLINE');
      this.scheduleReconnect();
    }
  }

  public disconnect() {
    this.explicitDisconnect = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopHeartbeat();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.setStatus('OFFLINE');
  }

  public subscribe(eventType: string, handler: WsMessageHandler) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(handler);

    return () => {
      const handlers = this.listeners.get(eventType);
      if (handlers) {
        handlers.delete(handler);
      }
    };
  }

  private scheduleReconnect() {
    if (this.explicitDisconnect) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), this.maxReconnectDelay);
    this.reconnectAttempts++;

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 25000);
  }

  private stopHeartbeat() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }
}

export const websocketService = new WebSocketService();
