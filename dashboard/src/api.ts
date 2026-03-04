import type { AuditResult, Finding, PlatformStats, AuditHistoryEntry, WSEvent } from './types';

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

interface RawTask {
  task_id: string;
  status: string;
  prompt: string;
  phases: { phase: string; duration_ms: number | null; started_at: string }[];
  results: { filename: string; size_bytes: number; download_url: string }[];
  cost: { total_cost_usd: number; savings_pct: number; always_on_equivalent_monthly: number };
  droplet: { id: number; ip: string; slug: string; lifetime_seconds: number };
  error: string | null;
}

async function fetchSpacesFile(results: RawTask['results'], filename: string): Promise<string | null> {
  const file = results.find(r => r.filename === filename);
  if (!file || !file.download_url) return null;
  try {
    const res = await fetch(file.download_url);
    if (!res.ok) return null;
    return res.text();
  } catch {
    return null;
  }
}

export async function getTaskStatus(taskId: string): Promise<AuditResult> {
  const raw: RawTask = await request(`/api/v1/tasks/${taskId}`);

  // If task not completed yet, return a minimal result
  if (raw.status !== 'completed') {
    return {
      task_id: raw.task_id,
      repo_url: raw.prompt || '',
      repo_name: raw.prompt?.replace('CodeScope audit: ', '').replace(/https?:\/\/github\.com\//, '').split(' ')[0] || '',
      branch: 'main',
      language: 'detecting...',
      status: raw.status as AuditResult['status'],
      risk_score: 0,
      layers: [],
      findings: [],
      summary: '',
      cost_usd: raw.cost?.total_cost_usd || 0,
      duration_seconds: raw.droplet?.lifetime_seconds || 0,
      droplet_ip: raw.droplet?.ip || '',
      provision_time: 0,
      started_at: raw.phases?.[0]?.started_at || new Date().toISOString(),
      completed_at: null,
    };
  }

  // Task completed - try to download the actual findings from Spaces
  const repoName = raw.prompt?.replace('CodeScope audit: ', '').replace(/https?:\/\/github\.com\//, '').split(' ')[0] || '';

  let findings: AuditResult['findings'] = [];
  let summary = '';
  let riskScore = 0;
  let language = 'unknown';
  let layers: AuditResult['layers'] = [];

  // Try to fetch and parse the stdout.log for layer info
  const logContent = await fetchSpacesFile(raw.results, 'stdout.log');
  if (logContent) {
    // Extract layer results from log lines like "[Layer 1/7] ... complete: N findings"
    const layerNames = ['SAST Analysis', 'Dependencies', 'Secrets Detection', 'License Compliance', 'Test Coverage', 'Repo Health', 'AI Synthesis'];
    const layerRe = /\[Layer (\d)\/7\].*?complete[:\s]+(\d+)\s/gi;
    let match;
    while ((match = layerRe.exec(logContent)) !== null) {
      const idx = parseInt(match[1]) - 1;
      if (idx >= 0 && idx < 7) {
        if (!layers[idx]) {
          layers[idx] = { id: idx + 1, name: layerNames[idx] || `Layer ${idx + 1}`, description: '', status: 'done', findings: parseInt(match[2]) || 0, duration: null };
        }
      }
    }
    // Fill missing layers
    for (let i = 0; i < 7; i++) {
      if (!layers[i]) {
        layers[i] = { id: i + 1, name: layerNames[i], description: '', status: 'done', findings: 0, duration: null };
      }
    }

    // Extract language
    const langMatch = logContent.match(/Language:\s*(\w+)/i);
    if (langMatch) language = langMatch[1];

    // Extract risk score
    const riskMatch = logContent.match(/Risk Score.*?(\d+)/i);
    if (riskMatch) riskScore = parseInt(riskMatch[1]);
  }

  // Try to download findings.json from the output archive
  // The archive has report.md and findings.json inside
  // Since we can't easily untar in browser, extract findings from the log
  if (logContent) {
    // Parse SAST findings from log
    const findingRe = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*`?([^`\n]+?)`?\s*(?:L(\d+))?:\s*(\w+)\s*-\s*(.+)/gi;
    let fMatch;
    let fIndex = 0;
    while ((fMatch = findingRe.exec(logContent)) !== null) {
      findings.push({
        id: `f${++fIndex}`,
        severity: fMatch[1].toLowerCase() as Finding['severity'],
        category: fMatch[4].includes('prompt') || fMatch[4].includes('llm') ? 'AI Code Safety' :
                  fMatch[4].includes('cors') || fMatch[4].includes('csrf') || fMatch[4].includes('sql') || fMatch[4].includes('xss') ? 'OWASP Top 10' :
                  fMatch[4].includes('hallucin') ? 'Supply Chain' :
                  fMatch[4].includes('password') || fMatch[4].includes('secret') || fMatch[4].includes('key') ? 'Secrets Detection' : 'SAST',
        title: fMatch[5].trim().substring(0, 100),
        file: fMatch[2].trim(),
        line: fMatch[3] ? parseInt(fMatch[3]) : 0,
        description: fMatch[5].trim(),
        fix: '',
      });
    }

    // Extract AI summary from report section
    const summaryMatch = logContent.match(/Executive Summary\s*\n([\s\S]*?)(?:\n#|\nRisk Score|\n\*\*)/i);
    if (summaryMatch) {
      summary = summaryMatch[1].trim().substring(0, 500);
    }
    if (!summary) {
      summary = `Security audit of ${repoName} completed with ${findings.length} findings across 7 analysis layers.`;
    }
  }

  // Calculate duration from phases
  const totalDuration = raw.phases?.reduce((sum, p) => sum + (p.duration_ms ? p.duration_ms / 1000 : 0), 0) || 0;

  return {
    task_id: raw.task_id,
    repo_url: `https://github.com/${repoName}`,
    repo_name: repoName,
    branch: 'main',
    language,
    status: 'completed',
    risk_score: riskScore || Math.min(findings.length * 3, 100),
    layers: layers.length > 0 ? layers : [
      { id: 1, name: 'SAST Analysis', description: '', status: 'done', findings: findings.length, duration: null },
      { id: 2, name: 'Dependencies', description: '', status: 'done', findings: 0, duration: null },
      { id: 3, name: 'Secrets Detection', description: '', status: 'done', findings: 0, duration: null },
      { id: 4, name: 'License Compliance', description: '', status: 'done', findings: 0, duration: null },
      { id: 5, name: 'Test Coverage', description: '', status: 'done', findings: 0, duration: null },
      { id: 6, name: 'Repo Health', description: '', status: 'done', findings: 0, duration: null },
      { id: 7, name: 'AI Synthesis', description: '', status: 'done', findings: 0, duration: null },
    ],
    findings,
    summary,
    cost_usd: raw.cost?.total_cost_usd || 0.009,
    duration_seconds: totalDuration || raw.droplet?.lifetime_seconds || 0,
    droplet_ip: raw.droplet?.ip || '',
    provision_time: raw.phases?.find(p => p.phase === 'provisioning')?.duration_ms ? (raw.phases.find(p => p.phase === 'provisioning')!.duration_ms! / 1000) : 0,
    started_at: raw.phases?.[0]?.started_at || new Date().toISOString(),
    completed_at: new Date().toISOString(),
  };
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
