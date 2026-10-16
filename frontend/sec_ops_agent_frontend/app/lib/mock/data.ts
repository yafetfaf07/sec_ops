import type {
  AuditEntry,
  Incident,
  IncidentStatus,
  LogAction,
  LogEntry,
  RiskLevel,
  SchedulerSettings,
} from "~/lib/types";

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(20261016);

const USERS = [
  "alice.chen",
  "bram.veder",
  "carla.mendez",
  "dmitri.volkov",
  "elena.petrova",
  "farouk.hassan",
  "gita.rao",
  "hans.mueller",
  "ines.dupont",
  "jonas.berg",
  "kaya.tanaka",
  "liam.oconnor",
];

const CITIES: Record<string, string[]> = {
  Germany: ["Berlin", "Munich", "Hamburg", "Frankfurt"],
  "United States": ["Ashburn", "Portland", "Dallas", "Seattle"],
  Russia: ["Moscow", "Saint Petersburg"],
  "United Kingdom": ["London", "Manchester"],
  France: ["Paris", "Lyon"],
  "South Korea": ["Seoul"],
  Nigeria: ["Lagos"],
  "Brazil": ["Sao Paulo"],
  China: ["Beijing"],
  India: ["Bengaluru"],
};

const COUNTRIES = Object.keys(CITIES);

export const COUNTRIES_FALLBACK: string[] = COUNTRIES;

const AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
  "curl/8.4.0",
  "python-requests/2.31.0",
  "Go-http-client/2.0",
];

const FLAGGED: LogAction[] = ["Login Failed", "Privilege Escalation"];

function ip() {
  return `${randInt(1, 254)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
}

function randInt(min: number, max: number) {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

const NOW = Date.now();
const HOUR = 3600 * 1000;

function isoAgo(hoursAgo: number) {
  return new Date(NOW - hoursAgo * HOUR).toISOString();
}

// --- Logs -----------------------------------------------------------------
function generateLogs(count: number): LogEntry[] {
  const logs: LogEntry[] = [];
  for (let i = 0; i < count; i++) {
    const country = pick(COUNTRIES);
    const city = pick(CITIES[country]);
    const roll = rng();
    const action: LogAction =
      roll < 0.62
        ? "Login Success"
        : roll < 0.93
          ? "Login Failed"
          : "Privilege Escalation";
    const hoursAgo = rng() * 72;
    logs.push({
      log_id: `log_${(100000 + i).toString()}`,
      timestamp: isoAgo(hoursAgo),
      user_id: pick(USERS),
      ip_address: ip(),
      country,
      city,
      action,
      user_agent: pick(AGENTS),
      flagged: FLAGGED.includes(action),
    });
  }
  return logs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export const LOGS: LogEntry[] = generateLogs(260);

// --- Incidents ------------------------------------------------------------
function generateIncidents(count: number): Incident[] {
  const statuses: IncidentStatus[] = [
    "Open",
    "Open",
    "Open",
    "Acknowledged",
    "Acknowledged",
    "Resolved",
    "Resolved",
    "Open",
    "Resolved",
    "Open",
  ];
  const risks: RiskLevel[] = [
    "Low",
    "Medium",
    "High",
    "Critical",
    "Medium",
    "High",
    "Low",
    "Critical",
    "Medium",
    "High",
    "Low",
    "Medium",
  ];

  const flaggedLogs = LOGS.filter((l) => l.flagged);
  const incidents: Incident[] = [];

  for (let i = 0; i < count; i++) {
    const risk = risks[i % risks.length];
    const status = statuses[i % statuses.length];
    const detectedHoursAgo = rng() * 70;
    const detected = new Date(NOW - detectedHoursAgo * HOUR).toISOString();
    const country = pick(COUNTRIES);
    const confidence =
      risk === "Critical"
        ? randInt(72, 99)
        : risk === "High"
          ? randInt(52, 88)
          : randInt(0, 55);

    const start = Math.floor(rng() * flaggedLogs.length);
    const batchLogs = flaggedLogs.slice(start, start + 6).map((l) => l.log_id);

    incidents.push({
      id: `INC-${(2000 + i).toString()}`,
      risk_score: risk,
      status,
      ai_summary: summarize(risk, country, batchLogs.length),
      recommended_action: recommend(risk),
      abuseipdb_confidence: confidence,
      top_ip: ip(),
      country,
      detected_at: detected,
      acknowledged_at:
        status === "Acknowledged" || status === "Resolved"
          ? new Date(
              new Date(detected).getTime() + 40 * 60 * 1000,
            ).toISOString()
          : undefined,
      resolved_at:
        status === "Resolved"
          ? new Date(
              new Date(detected).getTime() + 3 * HOUR,
            ).toISOString()
          : undefined,
      batch_ref: `batch_${9000 + i}`,
      comments:
        status === "Resolved"
          ? [
              {
                author: "admin",
                role: "admin",
                body: "Blocked source IP at firewall level.",
                created_at: new Date(
                  new Date(detected).getTime() + 3 * HOUR,
                ).toISOString(),
              },
            ]
          : [],
    });
  }
  return incidents.sort((a, b) => b.detected_at.localeCompare(a.detected_at));
}

function summarize(risk: RiskLevel, country: string, n: number): string {
  const base = {
    Low: `Routine anomaly across ${n} flagged events. No coordinated pattern detected.`,
    Medium: `Unusual access pattern involving ${n} flagged events, largely originating from ${country}. Possible credential stuffing probing.`,
    High: `Likely brute-force campaign: ${n} failed logins in a short window, concentrated on privileged accounts, mostly from ${country}.`,
    Critical: `High-confidence compromise signal: privilege escalation paired with ${n} failed logins from ${country}. Implied attacker holds valid credentials.`,
  } as const;
  return base[risk];
}

function recommend(risk: RiskLevel): string {
  const map = {
    Low: "Monitor; no immediate action required.",
    Medium: "Review source IPs and enforce rate limiting on the login endpoint.",
    High: "Block offending IPs, force password reset for targeted accounts, enable MFA.",
    Critical: "Isolate affected accounts, block IPs at firewall, and audit privilege changes immediately.",
  } as const;
  return map[risk];
}

export const INCIDENTS: Incident[] = generateIncidents(34);

// --- Audit ----------------------------------------------------------------
function generateAudit(count: number): AuditEntry[] {
  const types = [
    { action_type: "AI_ANALYSIS_TRIGGER", details: "Sent flagged log batch to Gemini for anomaly analysis." },
    { action_type: "ALERT_SENT", details: "Dispatched critical incident notification via Slack webhook." },
    { action_type: "INCIDENT_RESOLVED", details: "Incident marked resolved by admin with remediation comment." },
    { action_type: "SCHEDULED_SCAN", details: "Cloud Scheduler daily scan executed successfully." },
    { action_type: "THREAT_INTEL_ENRICH", details: "Queried AbuseIPDB for abuse confidence score (cached 24h)." },
    { action_type: "INCIDENT_ACKNOWLEDGED", details: "Analyst acknowledged incident for triage." },
  ];

  const entries: AuditEntry[] = [];
  for (let i = 0; i < count; i++) {
    const t = types[i % types.length];
    const isSystem = i % 3 !== 0;
    entries.push({
      id: `audit_${700000 + i}`,
      timestamp: isoAgo(rng() * 70),
      user_id: isSystem ? "SYSTEM" : pick(["admin", "analyst"]),
      action_type: t.action_type,
      details: t.details,
    });
  }
  return entries.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export const AUDIT: AuditEntry[] = generateAudit(72);

export const SETTINGS: SchedulerSettings = {
  enabled: true,
  cron_hour_utc: 2,
  timezone: "UTC",
  slack_webhook_set: true,
  discord_webhook_set: false,
  gemini_model: "gemini-1.5-flash",
  abuseipdb_enabled: true,
};
