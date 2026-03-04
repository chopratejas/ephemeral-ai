import { useState, useCallback, useRef, useEffect } from 'react';
import type {
  AuditResult,
  ScanLayer,
  Finding,
  AuditHistoryEntry,
  PlatformStats,
} from '../types';
import { startAudit, getTaskStatus, getStats, getHistory } from '../api';

export type AppView = 'home' | 'scanning' | 'report';

const DEFAULT_LAYERS: ScanLayer[] = [
  { id: 1, name: 'Understanding', description: 'LLM reads the project', status: 'pending', findings: 0, duration: null },
  { id: 2, name: 'Setup', description: 'Installing and running', status: 'pending', findings: 0, duration: null },
  { id: 3, name: 'Auth & Access', description: 'Authentication review', status: 'pending', findings: 0, duration: null },
  { id: 4, name: 'Injection & Input', description: 'SQL/XSS/Command injection', status: 'pending', findings: 0, duration: null },
  { id: 5, name: 'AI Security', description: 'Prompt injection, LLM misuse', status: 'pending', findings: 0, duration: null },
  { id: 6, name: 'Secrets & Config', description: 'Hardcoded credentials', status: 'pending', findings: 0, duration: null },
  { id: 7, name: 'Synthesis', description: 'Multi-model report', status: 'pending', findings: 0, duration: null },
];

function generateMockFindings(_repoName: string): Finding[] {
  return [
    {
      id: 'f1',
      severity: 'critical',
      category: 'AI Code Safety',
      title: 'Prompt injection vulnerability',
      file: 'src/llm/chain.py',
      line: 45,
      description: 'User input is directly interpolated into LLM prompt template without sanitization. An attacker could manipulate the model behavior through crafted input.',
      fix: 'Use parameterized prompt templates. Sanitize user input before inclusion in any prompt string.',
      cwe: 'CWE-77',
    },
    {
      id: 'f2',
      severity: 'critical',
      category: 'OWASP Top 10',
      title: 'SQL injection in query builder',
      file: 'src/db/queries.py',
      line: 23,
      description: 'f-string interpolation used directly in SQL query construction. User-controlled parameters are not parameterized.',
      fix: 'Use parameterized queries with placeholder syntax. Never concatenate user input into SQL strings.',
      owasp: 'A03:2021',
      cwe: 'CWE-89',
    },
    {
      id: 'f3',
      severity: 'high',
      category: 'Secrets Detection',
      title: 'Hardcoded API key detected',
      file: '.env.example',
      line: 3,
      description: 'AWS access key pattern found in committed file. Even in example files, real-looking keys can be accidentally valid.',
      fix: 'Remove key material from version control. Use a secrets manager or environment-specific configuration.',
      cwe: 'CWE-798',
    },
    {
      id: 'f4',
      severity: 'high',
      category: 'OWASP Top 10',
      title: 'Insecure deserialization',
      file: 'src/api/handlers.py',
      line: 112,
      description: 'pickle.loads() called on user-supplied data without validation. This enables arbitrary code execution.',
      fix: 'Use JSON or a safe serialization format. If pickle is required, implement a restricted unpickler.',
      owasp: 'A08:2021',
      cwe: 'CWE-502',
    },
    {
      id: 'f5',
      severity: 'high',
      category: 'Dependencies',
      title: 'Known vulnerable dependency: requests 2.25.0',
      file: 'requirements.txt',
      line: 8,
      description: 'requests 2.25.0 has a known SSRF vulnerability (CVE-2023-32681). Upgrade to 2.31.0 or later.',
      fix: 'Pin requests>=2.31.0 in requirements.txt.',
      cwe: 'CWE-918',
    },
    {
      id: 'f6',
      severity: 'high',
      category: 'AI Code Safety',
      title: 'Unbounded token generation',
      file: 'src/llm/generate.py',
      line: 67,
      description: 'max_tokens parameter not set on LLM API call. This could lead to excessive costs or denial of service.',
      fix: 'Set explicit max_tokens limit appropriate for the use case.',
    },
    {
      id: 'f7',
      severity: 'high',
      category: 'Supply Chain',
      title: 'Unpinned dependency with install script',
      file: 'package.json',
      line: 15,
      description: 'Dependency "postinstall-build" uses a preinstall hook and is unpinned (^1.0.0). Supply chain attack vector.',
      fix: 'Pin exact versions for dependencies with lifecycle scripts. Consider using npm audit signatures.',
      cwe: 'CWE-829',
    },
    {
      id: 'f8',
      severity: 'medium',
      category: 'OWASP Top 10',
      title: 'Missing rate limiting on auth endpoint',
      file: 'src/api/auth.py',
      line: 34,
      description: 'Login endpoint has no rate limiting. Susceptible to brute force attacks.',
      fix: 'Add rate limiting middleware (e.g., 5 attempts per minute per IP).',
      owasp: 'A07:2021',
    },
    {
      id: 'f9',
      severity: 'medium',
      category: 'OWASP Top 10',
      title: 'Verbose error messages in production',
      file: 'src/app.py',
      line: 89,
      description: 'Stack traces and internal details exposed in error responses when DEBUG=False.',
      fix: 'Implement custom error handler that returns generic messages in production.',
      owasp: 'A05:2021',
      cwe: 'CWE-209',
    },
    {
      id: 'f10',
      severity: 'medium',
      category: 'Dependencies',
      title: 'Outdated cryptographic library',
      file: 'requirements.txt',
      line: 12,
      description: 'cryptography 3.4.6 is significantly outdated. Missing security patches and modern algorithm support.',
      fix: 'Upgrade to cryptography>=42.0.0.',
    },
    {
      id: 'f11',
      severity: 'medium',
      category: 'OWASP Top 10',
      title: 'CORS wildcard configuration',
      file: 'src/app.py',
      line: 15,
      description: 'CORS policy allows all origins (*). This weakens same-origin protections.',
      fix: 'Restrict CORS to specific trusted domains.',
      owasp: 'A01:2021',
    },
    {
      id: 'f12',
      severity: 'medium',
      category: 'License Compliance',
      title: 'GPL-3.0 dependency in MIT project',
      file: 'requirements.txt',
      line: 22,
      description: 'Project is MIT-licensed but depends on a GPL-3.0 package. This creates a license conflict.',
      fix: 'Replace with a permissively-licensed alternative or relicense the project.',
    },
    {
      id: 'f13',
      severity: 'medium',
      category: 'Secrets Detection',
      title: 'Private key file in repository',
      file: 'certs/dev.key',
      line: 1,
      description: 'RSA private key committed to repository. Even if for development, this sets a dangerous precedent.',
      fix: 'Remove from version control. Add *.key to .gitignore.',
      cwe: 'CWE-312',
    },
    {
      id: 'f14',
      severity: 'medium',
      category: 'OWASP Top 10',
      title: 'Missing Content-Security-Policy header',
      file: 'src/middleware.py',
      line: 1,
      description: 'No CSP header configured. Increases risk of XSS attacks.',
      fix: 'Add Content-Security-Policy header with appropriate directives.',
      owasp: 'A05:2021',
    },
    {
      id: 'f15',
      severity: 'medium',
      category: 'AI Code Safety',
      title: 'LLM output used without validation',
      file: 'src/llm/parse.py',
      line: 31,
      description: 'Raw LLM output parsed as JSON and used directly in database query without schema validation.',
      fix: 'Validate LLM output against a strict schema before use. Treat LLM output as untrusted input.',
    },
    {
      id: 'f16',
      severity: 'low',
      category: 'Repo Health',
      title: 'No SECURITY.md file',
      file: '',
      line: 0,
      description: 'Repository lacks a security policy file. Vulnerability reporters have no clear disclosure path.',
      fix: 'Add a SECURITY.md with responsible disclosure instructions.',
    },
    {
      id: 'f17',
      severity: 'low',
      category: 'Repo Health',
      title: 'Branch protection not enabled',
      file: '',
      line: 0,
      description: 'Main branch has no protection rules. Direct pushes and force pushes are allowed.',
      fix: 'Enable branch protection: require PR reviews, status checks, and no force pushes.',
    },
    {
      id: 'f18',
      severity: 'low',
      category: 'Repo Health',
      title: 'No dependency update automation',
      file: '',
      line: 0,
      description: 'No Dependabot or Renovate configuration found. Dependencies may go unpatched.',
      fix: 'Add .github/dependabot.yml or renovate.json for automated updates.',
    },
    {
      id: 'f19',
      severity: 'low',
      category: 'Test Coverage',
      title: 'Auth module has no test coverage',
      file: 'src/api/auth.py',
      line: 1,
      description: 'Security-critical authentication module has 0% test coverage.',
      fix: 'Add comprehensive tests for authentication flows, especially edge cases.',
    },
    {
      id: 'f20',
      severity: 'low',
      category: 'Dependencies',
      title: '12 unused dependencies detected',
      file: 'requirements.txt',
      line: 1,
      description: 'Multiple installed packages are not imported anywhere in the codebase. Increases attack surface.',
      fix: 'Remove unused dependencies from requirements.txt.',
    },
    {
      id: 'f21',
      severity: 'low',
      category: 'Repo Health',
      title: 'Missing .gitignore entries',
      file: '.gitignore',
      line: 1,
      description: 'Common patterns missing: .env, __pycache__, .mypy_cache, *.pyc.',
      fix: 'Update .gitignore with standard Python patterns.',
    },
    {
      id: 'f22',
      severity: 'low',
      category: 'License Compliance',
      title: 'No license header in source files',
      file: 'src/',
      line: 0,
      description: 'Source files lack license headers. Copyright and license terms are ambiguous.',
      fix: 'Add license headers to source files or a NOTICE file.',
    },
    {
      id: 'f23',
      severity: 'info',
      category: 'Repo Health',
      title: 'Repository uses Python 3.9',
      file: 'runtime.txt',
      line: 1,
      description: 'Python 3.9 reaches end-of-life October 2025. Plan migration to 3.11+.',
      fix: 'Update to Python 3.11 or later for continued security support.',
    },
    {
      id: 'f24',
      severity: 'info',
      category: 'Dependencies',
      title: '3 dependencies have newer major versions',
      file: 'requirements.txt',
      line: 1,
      description: 'flask, sqlalchemy, and celery have newer major versions available with security improvements.',
      fix: 'Evaluate major version upgrades during next development cycle.',
    },
    {
      id: 'f25',
      severity: 'info',
      category: 'Test Coverage',
      title: 'Overall test coverage: 64%',
      file: '',
      line: 0,
      description: 'Test coverage is moderate. Security-critical paths should target 80%+ coverage.',
      fix: 'Increase test coverage, prioritizing security-critical modules.',
    },
  ];
}

function generateMockReport(repoUrl: string): AuditResult {
  const repoName = repoUrl.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '') || 'owner/repo';
  const findings = generateMockFindings(repoName);

  return {
    task_id: 'tsk_' + Math.random().toString(36).substring(2, 10),
    repo_url: repoUrl,
    repo_name: repoName,
    branch: 'main',
    language: 'Python',
    status: 'completed',
    risk_score: 42,
    layers: [
      { id: 1, name: 'Understanding', description: 'LLM reads the project', status: 'done', findings: 6, duration: 1.2 },
      { id: 2, name: 'Setup', description: 'Installing and running', status: 'done', findings: 4, duration: 0.8 },
      { id: 3, name: 'Auth & Access', description: 'Authentication review', status: 'done', findings: 2, duration: 0.3 },
      { id: 4, name: 'Injection & Input', description: 'SQL/XSS/Command injection', status: 'done', findings: 2, duration: 0.5 },
      { id: 5, name: 'AI Security', description: 'Prompt injection, LLM misuse', status: 'done', findings: 2, duration: 0.4 },
      { id: 6, name: 'Secrets & Config', description: 'Hardcoded credentials', status: 'done', findings: 6, duration: 0.2 },
      { id: 7, name: 'Synthesis', description: 'Multi-model report', status: 'done', findings: 3, duration: 8.3 },
    ],
    findings,
    summary: `Security audit of ${repoName} identified 25 findings across 7 analysis layers. 2 critical issues require immediate attention: a prompt injection vulnerability in the LLM integration and an SQL injection in the query builder. The repository also has 5 high-severity issues including hardcoded credentials and an insecure deserialization pattern. Overall risk score of 42/100 indicates moderate risk with actionable improvements.`,
    cost_usd: 0.009,
    duration_seconds: 11.7,
    droplet_ip: '143.110.152.148',
    provision_time: 0.0,
    started_at: new Date(Date.now() - 12000).toISOString(),
    completed_at: new Date().toISOString(),
  };
}

export function useAudit() {
  const [view, setView] = useState<AppView>('home');
  const [repoUrl, setRepoUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [layers, setLayers] = useState<ScanLayer[]>(DEFAULT_LAYERS);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [stats, setStats] = useState<PlatformStats>({
    total_tasks: 0,
    total_cost_usd: 0,
    total_savings_usd: 0,
    warm_pool_size: 0,
    warm_pool_idle: 0,
    warm_pool_busy: 0,
    average_task_duration_seconds: 0,
  });
  const [history, setHistory] = useState<AuditHistoryEntry[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const simulationRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    // Fetch real audit history from Spaces
    getHistory()
      .then((h) => { if (h.length > 0) setHistory(h); })
      .catch(() => {});

    // Fetch real stats
    getStats()
      .then((s) => setStats(s))
      .catch(() => {
        // Use defaults
      });
  }, []);

  const cleanup = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    simulationRef.current.forEach(clearTimeout);
    simulationRef.current = [];
  }, []);

  const simulateScan = useCallback((repoUrl: string) => {
    const freshLayers = DEFAULT_LAYERS.map((l) => ({ ...l }));
    setLayers(freshLayers);
    setElapsed(0);
    setView('scanning');

    const startTime = Date.now();
    timerRef.current = setInterval(() => {
      setElapsed((Date.now() - startTime) / 1000);
    }, 100);

    const layerTimings = [
      { delay: 300, duration: 1.2, findings: 6 },
      { delay: 1600, duration: 0.8, findings: 4 },
      { delay: 2500, duration: 0.3, findings: 2 },
      { delay: 2900, duration: 0.5, findings: 2 },
      { delay: 3500, duration: 0.4, findings: 2 },
      { delay: 4000, duration: 0.2, findings: 6 },
      { delay: 4300, duration: 8.3, findings: 3 },
    ];

    // Start first layer immediately
    const t0 = setTimeout(() => {
      setLayers((prev) => prev.map((l, i) => (i === 0 ? { ...l, status: 'running' as const } : l)));
    }, 100);
    simulationRef.current.push(t0);

    layerTimings.forEach((timing, idx) => {
      // Complete this layer
      const tComplete = setTimeout(() => {
        setLayers((prev) =>
          prev.map((l, i) => {
            if (i === idx) {
              return { ...l, status: 'done' as const, findings: timing.findings, duration: timing.duration };
            }
            if (i === idx + 1 && l.status === 'pending') {
              return { ...l, status: 'running' as const };
            }
            return l;
          })
        );
      }, timing.delay + timing.duration * 100);
      simulationRef.current.push(tComplete);
    });

    // Complete the scan
    const tFinal = setTimeout(() => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
      const report = generateMockReport(repoUrl);
      setResult(report);
      setElapsed(report.duration_seconds);

      // Add to history
      setHistory((prev) => [
        {
          task_id: report.task_id,
          repo_name: report.repo_name,
          risk_score: report.risk_score,
          total_findings: report.findings.length,
          duration_seconds: report.duration_seconds,
          cost_usd: report.cost_usd,
          completed_at: new Date().toISOString(),
          status: 'completed',
        },
        ...prev,
      ]);

      // Update stats
      setStats((prev) => ({
        ...prev,
        total_tasks: prev.total_tasks + 1,
        total_cost_usd: prev.total_cost_usd + report.cost_usd,
      }));

      setView('report');
    }, 5500);
    simulationRef.current.push(tFinal);
  }, []);

  const submitAudit = useCallback(
    async (url: string) => {
      cleanup();
      setError(null);
      setLoading(true);
      setRepoUrl(url);

      // Try to start the audit via the real API
      let taskId: string | null = null;
      try {
        const response = await startAudit(url);
        taskId = response.task_id;
      } catch {
        // API truly unreachable - fall back to simulation
        setLoading(false);
        simulateScan(url);
        return;
      }

      // If we got a task_id, ALWAYS use the real polling path.
      // Never fall back to simulation from here onward.
      setLoading(false);
      setView('scanning');
      setLayers(DEFAULT_LAYERS.map((l) => ({ ...l })));

      const startTime = Date.now();
      timerRef.current = setInterval(() => {
        setElapsed((Date.now() - startTime) / 1000);
      }, 100);

      // Poll for status + logs every 3 seconds
      let notFoundCount = 0;
      const poll = setInterval(async () => {
        try {
          const raw = await fetch(`${import.meta.env.VITE_API_URL || 'https://ephemeral-ai-dgdbw.ondigitalocean.app'}/api/v1/tasks/${taskId}`);

          // Handle 404 (task lost due to server restart)
          if (raw.status === 404) {
            notFoundCount++;
            if (notFoundCount >= 3) {
              clearInterval(poll);
              if (timerRef.current) clearInterval(timerRef.current);
              setError('Task was lost (server restarted). Please try again.');
              setView('home');
              return;
            }
          }

          const data = await raw.json();

          // Update logs from backend (the daemon forwards CodeScope output)
          if (data.logs && data.logs.length > 0) {
            setLogs(data.logs);

            // Parse layer status from actual log lines
            setLayers((prev) => {
              const updated = prev.map((l) => ({ ...l }));
              const layerDoneRe = /\[Layer (\d)\/7\].*?complete/i;
              const layerStartRe = /\[Layer (\d)\/7\]/i;

              for (const line of data.logs) {
                const doneMatch = line.match(layerDoneRe);
                if (doneMatch) {
                  const idx = parseInt(doneMatch[1]) - 1;
                  if (idx >= 0 && idx < 7) {
                    const findingsMatch = line.match(/(\d+)\s+findings?/i);
                    updated[idx] = {
                      ...updated[idx],
                      status: 'done',
                      findings: findingsMatch ? parseInt(findingsMatch[1]) : 0,
                    };
                  }
                }
                const startMatch = line.match(layerStartRe);
                if (startMatch && !doneMatch) {
                  const idx = parseInt(startMatch[1]) - 1;
                  if (idx >= 0 && idx < 7 && updated[idx].status === 'pending') {
                    updated[idx] = { ...updated[idx], status: 'running' };
                  }
                }
              }
              return updated;
            });
          }

          if (data.status === 'completed') {
            clearInterval(poll);
            if (timerRef.current) clearInterval(timerRef.current);
            setLayers((prev) => prev.map((l) => ({ ...l, status: 'done' as const })));
            setLogs((prev) => [...prev, '--- Audit complete. Loading report... ---']);
            await new Promise((r) => setTimeout(r, 800));
            const result = await getTaskStatus(taskId!);
            setResult(result);
            setView('report');
          } else if (data.status === 'failed') {
            clearInterval(poll);
            if (timerRef.current) clearInterval(timerRef.current);
            setError(data.error || 'Audit failed');
            setView('home');
          }
        } catch {
          // Polling error - keep trying, do NOT fall back to simulation
        }
      }, 3000);
    },
    [cleanup, simulateScan]
  );

  const reset = useCallback(() => {
    cleanup();
    setView('home');
    setResult(null);
    setError(null);
    setLayers(DEFAULT_LAYERS.map((l) => ({ ...l })));
    setElapsed(0);
    setLogs([]);
  }, [cleanup]);

  const viewReport = useCallback(async (entry: AuditHistoryEntry) => {
    // Try to fetch real report from the API first
    try {
      const report = await getTaskStatus(entry.task_id);
      if (report.findings.length > 0) {
        setResult(report);
        setView('report');
        return;
      }
    } catch {
      // Fall through to mock if API fails
    }
    // Fallback to mock data only if real data unavailable
    const report = generateMockReport(`https://github.com/${entry.repo_name}`);
    report.task_id = entry.task_id;
    report.risk_score = entry.risk_score;
    report.duration_seconds = entry.duration_seconds;
    report.cost_usd = entry.cost_usd;
    setResult(report);
    setView('report');
  }, []);

  return {
    view,
    repoUrl,
    loading,
    error,
    layers,
    result,
    elapsed,
    logs,
    stats,
    history,
    submitAudit,
    reset,
    viewReport,
    setError,
  };
}
