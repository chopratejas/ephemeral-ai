import type { AuditResult, PlatformStats, AuditHistoryEntry, WSEvent } from './types';

const API_BASE = import.meta.env.VITE_API_URL || 'https://ephemeral-ai-dgdbw.ondigitalocean.app';

function wsBase(): string {
  const url = new URL(API_BASE);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.toString().replace(/\/$/, '');
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
    },
    ...options,
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API error ${res.status}: ${body || res.statusText}`);
  }

  return res.json();
}

export async function startAudit(repoUrl: string, branch = 'main'): Promise<{ task_id: string; status: string; websocket_url: string }> {
  return request('/api/v1/audit', {
    method: 'POST',
    body: JSON.stringify({ repo_url: repoUrl, branch }),
  });
}

export async function getTaskStatus(taskId: string): Promise<AuditResult> {
  return request(`/api/v1/tasks/${taskId}`);
}

export async function getStats(): Promise<PlatformStats> {
  return request('/api/v1/stats');
}

export async function getHistory(): Promise<AuditHistoryEntry[]> {
  return request('/api/v1/history');
}

export function connectWebSocket(
  taskId: string,
  onMessage: (event: WSEvent) => void,
  onError?: (error: Event) => void,
  onClose?: () => void
): WebSocket {
  const ws = new WebSocket(`${wsBase()}/ws/tasks/${taskId}`);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as WSEvent;
      onMessage(data);
    } catch {
      console.error('Failed to parse WebSocket message:', event.data);
    }
  };

  ws.onerror = (event) => {
    console.error('WebSocket error:', event);
    onError?.(event);
  };

  ws.onclose = () => {
    onClose?.();
  };

  return ws;
}

export { API_BASE };
