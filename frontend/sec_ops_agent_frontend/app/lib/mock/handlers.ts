import type {
  AppRole,
  AuditEntry,
  AuthUser,
  DashboardSummary,
  Incident,
  LogAction,
  NLQueryResult,
  RiskLevel,
  SchedulerSettings,
} from "~/lib/types";
import { AUDIT, INCIDENTS, LOGS, SETTINGS, COUNTRIES_FALLBACK } from "./data";

// Mutable in-memory store (stands in for the SQLite/Postgres backend).
const incidents: Incident[] = INCIDENTS.map((i) => ({
  ...i,
  comments: [...i.comments],
}));
const audit: AuditEntry[] = [...AUDIT];
const settings: SchedulerSettings = { ...SETTINGS };

function delay(ms = 240) {
  return new Promise((r) => setTimeout(r, ms + Math.random() * 160));
}

function pushAudit(
  user_id: string,
  action_type: string,
  details: string,
) {
  audit.unshift({
    id: `audit_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    timestamp: new Date().toISOString(),
    user_id,
    action_type,
    details,
  });
}

// --- Auth -------------------------------------------------------------
// Mock mode has no real credential store: any password is accepted and the
// role is derived from the email's local part (admin@…, analyst@…,
// viewer@…), so a demo without a backend can still exercise every RBAC path.
const MOCK_USERS: Record<AppRole, AuthUser> = {
  admin: { id: "mock-admin", name: "Admin", email: "admin@example.com", role: "admin" },
  analyst: { id: "mock-analyst", name: "Analyst", email: "analyst@example.com", role: "analyst" },
  viewer: { id: "mock-viewer", name: "Viewer", email: "viewer@example.com", role: "viewer" },
};

let mockSessionUser: AuthUser | null = null;

export async function login(
  email: string,
  _password: string,
): Promise<{ access_token: string; user: AuthUser }> {
  await delay(300);
  const local = email.split("@")[0]?.toLowerCase();
  const role: AppRole =
    local === "analyst" ? "analyst" : local === "viewer" ? "viewer" : "admin";
  const user = { ...MOCK_USERS[role], email };
  mockSessionUser = user;
  pushAudit(user.email, "USER_LOGIN", `User ${user.email} signed in (mock).`);
  return { access_token: "mock-token", user };
}

export async function me(): Promise<AuthUser> {
  await delay(120);
  if (!mockSessionUser) throw new Error("not authenticated");
  return mockSessionUser;
}

export async function refresh(): Promise<{ access_token: string; user: AuthUser }> {
  await delay(120);
  if (!mockSessionUser) throw new Error("not authenticated");
  return { access_token: "mock-token", user: mockSessionUser };
}

export async function logout(): Promise<void> {
  await delay(100);
  mockSessionUser = null;
}

// --- Dashboard ------------------------------------------------------------
export async function getDashboardSummary(): Promise<DashboardSummary> {
  await delay(200);

  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const todayIso = startOfDay.toISOString();

  const logs_analyzed_today = LOGS.filter(
    (l) => l.timestamp >= todayIso,
  ).length;

  const active = incidents.filter((i) => i.status !== "Resolved");
  const active_threats: Record<RiskLevel, number> = {
    Low: 0,
    Medium: 0,
    High: 0,
    Critical: 0,
  };
  for (const i of active) active_threats[i.risk_score] += 1;

  return {
    logs_analyzed_today,
    active_threats,
    last_scan_time:
      audit.find((a) => a.action_type === "SCHEDULED_SCAN")?.timestamp ?? null,
    critical_incidents: active_threats.Critical + active_threats.High,
    flagged_logs: LOGS.filter((l) => l.flagged).length,
  };
}

// --- Incidents ------------------------------------------------------------
export interface IncidentQuery {
  status?: string;
  risk?: string;
  sort?: "detected_at" | "risk_score";
  dir?: "asc" | "desc";
}

const RISK_ORDER: Record<RiskLevel, number> = {
  Low: 0,
  Medium: 1,
  High: 2,
  Critical: 3,
};

export async function getIncidents(
  q: IncidentQuery = {},
): Promise<Incident[]> {
  await delay();
  let rows = [...incidents];
  if (q.status && q.status !== "All") {
    rows = rows.filter((i) => i.status === q.status);
  }
  if (q.risk && q.risk !== "All") {
    rows = rows.filter((i) => i.risk_score === q.risk);
  }
  const dir = q.dir === "asc" ? 1 : -1;
  const sort = q.sort ?? "detected_at";
  rows.sort((a, b) => {
    if (sort === "risk_score") {
      return (RISK_ORDER[a.risk_score] - RISK_ORDER[b.risk_score]) * dir;
    }
    return a.detected_at.localeCompare(b.detected_at) * dir;
  });
  return rows;
}

export async function getIncidentById(id: string): Promise<Incident> {
  await delay(120);
  const found = incidents.find((i) => i.id === id);
  if (!found) throw new Error("Incident not found");
  return found;
}

export async function acknowledgeIncident(id: string): Promise<Incident> {
  await delay(180);
  const inc = incidents.find((i) => i.id === id);
  if (!inc) throw new Error("Incident not found");
  const actor = mockSessionUser?.email ?? "unknown";
  inc.status = "Acknowledged";
  inc.acknowledged_at = new Date().toISOString();
  pushAudit(
    actor,
    "INCIDENT_ACKNOWLEDGED",
    `Incident ${id} acknowledged by ${actor}.`,
  );
  return { ...inc };
}

export async function resolveIncident(
  id: string,
  comment: string,
): Promise<Incident> {
  await delay(220);
  const inc = incidents.find((i) => i.id === id);
  if (!inc) throw new Error("Incident not found");
  const actor = mockSessionUser?.email ?? "unknown";
  inc.status = "Resolved";
  inc.resolved_at = new Date().toISOString();
  inc.comments.push({
    author: actor,
    role: mockSessionUser?.role ?? "analyst",
    body: comment,
    created_at: new Date().toISOString(),
  });
  pushAudit(
    actor,
    "INCIDENT_RESOLVED",
    `Incident ${id} resolved by ${actor}.`,
  );
  return { ...inc };
}

// --- Logs -----------------------------------------------------------------
export interface LogQuery {
  action?: string;
  country?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

export interface LogPage {
  rows: LogEntryLite[];
  total: number;
  page: number;
  pageSize: number;
}

export type LogEntryLite = (typeof LOGS)[number];

export async function getLogs(q: LogQuery = {}): Promise<LogPage> {
  await delay();
  let rows = LOGS;
  if (q.action && q.action !== "All") {
    rows = rows.filter((l) => l.action === q.action);
  }
  if (q.country && q.country !== "All") {
    rows = rows.filter((l) => l.country === q.country);
  }
  if (q.search) {
    const s = q.search.toLowerCase();
    rows = rows.filter(
      (l) =>
        l.user_id.toLowerCase().includes(s) ||
        l.ip_address.includes(s) ||
        l.log_id.includes(s),
    );
  }
  const pageSize = q.pageSize ?? 12;
  const page = q.page ?? 1;
  const start = (page - 1) * pageSize;
  return {
    rows: rows.slice(start, start + pageSize),
    total: rows.length,
    page,
    pageSize,
  };
}

export async function getLogCountries(): Promise<string[]> {
  return Array.from(new Set(LOGS.map((l) => l.country))).sort();
}

// --- Audit ----------------------------------------------------------------
export async function getAuditLog(): Promise<AuditEntry[]> {
  await delay(180);
  return [...audit];
}

// --- Scan -----------------------------------------------------------------
export async function runScan() {
  await delay(700);
  const actor = mockSessionUser?.email ?? "unknown";
  const analyzed = 14 + Math.floor(Math.random() * 20);
  const alerts = Math.floor(Math.random() * 3);
  pushAudit(
    actor,
    "SCHEDULED_SCAN",
    `Manual scan executed by ${actor}: analyzed ${analyzed} logs, ${alerts} new alerts.`,
  );
  return {
    logs_fetched: analyzed,
    analyzed,
    new_alerts: alerts,
    executed_at: new Date().toISOString(),
  };
}

// --- Natural language -----------------------------------------------------
const ACTIONS: { match: string[]; action: LogAction }[] = [
  { match: ["failed", "failure", "unsuccessful"], action: "Login Failed" },
  { match: ["privilege", "escalation", "elevation"], action: "Privilege Escalation" },
  { match: ["success", "successful", "logins"], action: "Login Success" },
];

function detectHours(text: string): number | null {
  if (/last\s+24\s*h|past\s+24|last\s+day|24\s*hours/i.test(text)) return 24;
  if (/last\s+hour|past\s+hour|1\s*hour/i.test(text)) return 1;
  if (/last\s+7\s*d|past\s+7|week/i.test(text)) return 24 * 7;
  if (/last\s+48|2\s*days/i.test(text)) return 48;
  return null;
}

export async function runNaturalLanguageQuery(
  query: string,
): Promise<NLQueryResult> {
  await delay(650);
  const text = query.toLowerCase();

  const filters: Record<string, string> = {};

  let action: LogAction | undefined;
  for (const a of ACTIONS) {
    if (a.match.some((m) => text.includes(m))) {
      action = a.action;
      break;
    }
  }

  const countries = COUNTRIES_FALLBACK;
  let country: string | undefined;
  for (const c of countries) {
    if (text.includes(c.toLowerCase())) {
      country = c;
      break;
    }
  }

  const hours = detectHours(text);

  const riskMatch = /critical/.test(text)
    ? "Critical"
    : /\bhigh\b/.test(text)
      ? "High"
      : /medium/.test(text)
        ? "Medium"
        : /\blow\b/.test(text)
          ? "Low"
          : null;

  if (action) filters.action = action;
  if (country) filters.country = country;
  if (hours) filters.window = `last ${hours}h`;
  if (riskMatch) filters.risk = riskMatch;

  // Match logs
  const cutoff = hours ? Date.now() - hours * 3600 * 1000 : null;
  let matchedLogs = LOGS.filter((l) => {
    if (action && l.action !== action) return false;
    if (country && l.country !== country) return false;
    if (cutoff && Date.parse(l.timestamp) < cutoff) return false;
    return true;
  });

  // Match incidents by risk/country
  const matchedIncidents = incidents
    .filter((i) => {
      if (riskMatch && i.risk_score !== riskMatch) return false;
      if (country && i.country !== country) return false;
      return true;
    })
    .map((i) => i.id);

  const parts: string[] = [];
  if (action) parts.push(`action = "${action}"`);
  if (country) parts.push(`country = "${country}"`);
  if (hours) parts.push(`timestamp within last ${hours} hours`);
  if (riskMatch) parts.push(`risk_score = "${riskMatch}"`);

  const interpretation =
    parts.length > 0
      ? `Understood as filtered query → ${parts.join(", ")}. Matched ${matchedLogs.length} logs and ${matchedIncidents.length} incidents.`
      : `No specific filter recognized; returning a broad overview across ${matchedLogs.length} logs and ${matchedIncidents.length} incidents.`;

  return {
    query,
    interpretation,
    filters_applied: filters,
    matched_incident_ids: matchedIncidents.slice(0, 40),
    matched_log_ids: matchedLogs.slice(0, 60).map((l) => l.log_id),
  };
}

// --- Settings -------------------------------------------------------------
export async function getSettings(): Promise<SchedulerSettings> {
  await delay(140);
  return { ...settings };
}

export async function updateSettings(
  patch: Partial<SchedulerSettings>,
): Promise<SchedulerSettings> {
  await delay(320);
  const actor = mockSessionUser?.email ?? "unknown";
  Object.assign(settings, patch);
  pushAudit(
    actor,
    "SETTINGS_UPDATED",
    `Scheduler/API configuration updated by ${actor}.`,
  );
  return { ...settings };
}
