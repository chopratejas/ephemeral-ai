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

  const layerNames = ['SAST Analysis', 'Dependencies', 'Secrets Detection', 'License Compliance', 'Test Coverage', 'Repo Health', 'AI Synthesis'];

  // Fetch the parsed report from the backend (extracts findings.json from tar)
  try {
    const reportData = await request<{
      findings: Record<string, unknown[]>;
      report_md: string;
      logs: string[];
    }>(`/api/v1/tasks/${raw.task_id}/report`);

    const rawFindings = reportData.findings || {};

    // Parse SAST findings
    const sast = (rawFindings.sast || []) as Array<{
      file: string; line: number; severity: string; rule: string; message: string; category: string;
    }>;
    let idx = 0;
    for (const f of sast) {
      findings.push({
        id: `f${++idx}`,
        severity: (f.severity || 'medium') as Finding['severity'],
        category: f.category === 'llm_security' ? 'AI Code Safety' :
                  f.category === 'ai_code' ? 'AI Patterns' :
                  f.category === 'owasp' ? 'OWASP Top 10' : 'SAST',
        title: f.message || f.rule,
        file: f.file || '',
        line: f.line || 0,
        description: f.message || '',
        fix: '',
      });
    }

    // Parse SCA findings
    const sca = (rawFindings.sca || []) as Array<{
      package: string; severity: string; vulnerability: string;
    }>;
    for (const f of sca) {
      findings.push({
        id: `f${++idx}`,
        severity: (f.severity || 'high') as Finding['severity'],
        category: f.vulnerability?.includes('HALLUCINATED') ? 'Supply Chain' : 'Dependencies',
        title: f.vulnerability || `Vulnerable: ${f.package}`,
        file: '',
        line: 0,
        description: f.vulnerability || '',
        fix: '',
      });
    }

    // Parse secrets
    const secrets = (rawFindings.secrets || []) as Array<{
      file: string; line: number; type: string;
    }>;
    for (const f of secrets) {
      findings.push({
        id: `f${++idx}`,
        severity: 'high',
        category: 'Secrets',
        title: `${f.type} detected`,
        file: f.file || '',
        line: f.line || 0,
        description: `Secret of type "${f.type}" found in code`,
        fix: 'Remove from version control. Use environment variables or a secrets manager.',
      });
    }

    // Build layer summary from findings counts
    const layerCounts = [
      sast.length,
      sca.length,
      secrets.length,
      ((rawFindings.licenses || []) as unknown[]).length,
      0, // tests (not a finding count)
      0, // health (not a finding count)
      0, // AI synthesis
    ];

    // Try to get layer counts from test/health objects
    const tests = rawFindings.tests as unknown;
    if (tests && typeof tests === 'object' && tests !== null && !Array.isArray(tests)) {
      layerCounts[4] = ((tests as Record<string, unknown>).test_files as number) || 0;
    }
    const health = rawFindings.repo_health as unknown;
    if (health && typeof health === 'object' && health !== null && !Array.isArray(health)) {
      const checks = ((health as Record<string, unknown>).checks || []) as unknown[];
      layerCounts[5] = checks.length;
    }

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
