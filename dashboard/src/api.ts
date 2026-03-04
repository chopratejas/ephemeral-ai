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
  logs: string[];
  error: string | null;
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

  // Task completed - fetch the full report from the backend
  const repoName = raw.prompt?.replace('CodeScope audit: ', '').replace(/https?:\/\/github\.com\//, '').split(' ')[0] || '';

  let findings: AuditResult['findings'] = [];
  let summary = '';
  let riskScore = 0;
  let language = 'unknown';
  let layers: AuditResult['layers'] = [];

  const layerNames = ['Understanding', 'Setup', 'Auth & Access', 'Injection & Input', 'AI Security', 'Secrets & Config', 'Synthesis'];

  // Fetch the parsed report from the backend (extracts findings.json from tar)
  try {
    const reportData = await request<{
      findings: Record<string, unknown[]>;
      report_md: string;
      logs: string[];
    }>(`/api/v1/tasks/${raw.task_id}/report`);

    const rawFindings = reportData.findings || {};

    // CodeScope v3 format: each category is { findings: [...], note?, error? }
    // Categories: ai_security, injection, auth, secrets, dependencies, error_handling, dynamic
    let idx = 0;

    const categoryLabels: Record<string, string> = {
      ai_security: 'AI Security',
      injection: 'Injection',
      auth: 'Auth & Access',
      secrets: 'Secrets',
      dependencies: 'Dependencies',
      error_handling: 'Error Handling',
      dynamic: 'Dynamic Test',
      sast: 'SAST',  // v2 compat
      sca: 'Dependencies',  // v2 compat
    };

    for (const [category, value] of Object.entries(rawFindings)) {
      // v3 format: { findings: [...] }
      let items: Array<Record<string, unknown>> = [];
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const obj = value as Record<string, unknown>;
        items = (obj.findings || []) as Array<Record<string, unknown>>;
      } else if (Array.isArray(value)) {
        // v2 format: flat array
        items = value as Array<Record<string, unknown>>;
      }

      for (const f of items) {
        findings.push({
          id: `f${++idx}`,
          severity: ((f.severity as string) || 'medium') as Finding['severity'],
          category: categoryLabels[category] || category,
          title: (f.title as string) || (f.message as string) || (f.rule as string) || 'Unknown',
          file: (f.file as string) || '',
          line: (f.line as number) || 0,
          description: (f.description as string) || (f.exploit as string) || (f.message as string) || '',
          fix: (f.fix as string) || (f.fix_code as string) || '',
          fix_code: (f.fix_code as string) || undefined,
        });
      }
    }

    // Build layer summary from v3 category counts
    const countFindings = (key: string): number => {
      const val = rawFindings[key];
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        return ((val as Record<string, unknown>).findings as unknown[] || []).length;
      }
      if (Array.isArray(val)) return val.length;
      return 0;
    };

    // Layers map to v3 phases: Understand, Setup, Auth, Injection, AI Security, Secrets, Synthesis
    const layerCounts = [
      0,  // Understanding (not a finding count)
      0,  // Setup (not a finding count)
      countFindings('auth'),
      countFindings('injection'),
      countFindings('ai_security'),
      countFindings('secrets') + countFindings('dependencies') + countFindings('error_handling'),
      countFindings('dynamic'),
    ];

    layers = layerNames.map((name, i) => ({
      id: i + 1,
      name,
      description: '',
      status: 'done' as const,
      findings: layerCounts[i] || 0,
      duration: null,
    }));

    // Extract summary and risk score from report markdown
    const reportMd = reportData.report_md || '';
    const riskMatch = reportMd.match(/Risk Score[:\s]*\*?\*?(\d+)/i);
    if (riskMatch) riskScore = parseInt(riskMatch[1]);

    const summaryMatch = reportMd.match(/Executive Summary[:\s]*\n([\s\S]*?)(?:\n---|\n##|\n\*\*)/i);
    if (summaryMatch) {
      summary = summaryMatch[1].replace(/[*#]/g, '').trim().substring(0, 600);
    }

    // Language from logs
    const logLines = reportData.logs || raw.logs || [];
    for (const l of logLines) {
      const lm = (l as string).match(/language.*?detected:\s*(\w+)/i);
      if (lm) { language = lm[1]; break; }
    }
  } catch (e) {
    console.error('Failed to fetch report:', e);
    summary = `Audit completed with findings. Report extraction failed.`;
  }

  if (!summary) {
    summary = `Security audit of ${repoName} completed with ${findings.length} findings across 7 analysis layers.`;
  }

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
      { id: 1, name: 'Understanding', description: '', status: 'done', findings: findings.length, duration: null },
      { id: 2, name: 'Setup', description: '', status: 'done', findings: 0, duration: null },
      { id: 3, name: 'Auth & Access', description: '', status: 'done', findings: 0, duration: null },
      { id: 4, name: 'Injection & Input', description: '', status: 'done', findings: 0, duration: null },
      { id: 5, name: 'AI Security', description: '', status: 'done', findings: 0, duration: null },
      { id: 6, name: 'Secrets & Config', description: '', status: 'done', findings: 0, duration: null },
      { id: 7, name: 'Synthesis', description: '', status: 'done', findings: 0, duration: null },
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
  try {
    const resp = await request<{ audits: Array<{
      task_id: string;
      repo_name: string;
      risk_score: number;
      total_findings: number;
      duration_seconds: number;
      language: string;
      framework: string;
      completed_at: string;
      summary: string;
    }> }>('/api/v1/audits/recent');

    return (resp.audits || []).map(a => ({
      task_id: a.task_id,
      repo_name: a.repo_name,
      risk_score: a.risk_score,
      total_findings: a.total_findings,
      duration_seconds: a.duration_seconds,
      cost_usd: 0.009,
      completed_at: a.completed_at,
      status: 'completed' as const,
      language: a.language || undefined,
      framework: a.framework || undefined,
    }));
  } catch {
    return [];
  }
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
