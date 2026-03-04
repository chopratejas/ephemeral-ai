export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type LayerStatus = 'pending' | 'running' | 'done' | 'error';

export type AuditStatus =
  | 'queued'
  | 'planning'
  | 'provisioning'
  | 'executing'
  | 'uploading'
  | 'cloning'
  | 'scanning'
  | 'analyzing'
  | 'completed'
  | 'failed'
  | 'destroyed'
  | 'error';

export interface ScanLayer {
  id: number;
  name: string;
  description: string;
  status: LayerStatus;
  findings: number;
  duration: number | null;
  detail?: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  file: string;
  line: number;
  description: string;
  fix: string;
  fix_code?: string;
  owasp?: string;
  cwe?: string;
}

export interface AuditResult {
  task_id: string;
  repo_url: string;
  repo_name: string;
  branch: string;
  language: string;
  status: AuditStatus;
  risk_score: number;
  layers: ScanLayer[];
  findings: Finding[];
  summary: string;
  cost_usd: number;
  duration_seconds: number;
  droplet_ip: string;
  provision_time: number;
  started_at: string;
  completed_at: string | null;
}

export interface AuditHistoryEntry {
  task_id: string;
  repo_name: string;
  risk_score: number;
  total_findings: number;
  duration_seconds: number;
  cost_usd: number;
  completed_at: string;
  status: AuditStatus;
  language?: string;
  framework?: string;
}

export interface PlatformStats {
  total_tasks: number;
  total_cost_usd: number;
  total_savings_usd: number;
  warm_pool_size: number;
  warm_pool_idle: number;
  warm_pool_busy: number;
  average_task_duration_seconds: number;
}

export interface WSEvent {
  event: string;
  data: Record<string, unknown>;
  timestamp?: string;
}
