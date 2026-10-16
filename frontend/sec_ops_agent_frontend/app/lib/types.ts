export type RiskLevel = "Low" | "Medium" | "High" | "Critical";

export type IncidentStatus = "Open" | "Acknowledged" | "Resolved";

export type LogAction =
  | "Login Success"
  | "Login Failed"
  | "Privilege Escalation";

export type AppRole = "admin" | "analyst" | "viewer";

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: AppRole;
}

export interface LogEntry {
  log_id: string;
  timestamp: string; // ISO 8601
  user_id: string;
  ip_address: string;
  country: string;
  city: string;
  action: LogAction;
  user_agent: string;
  flagged: boolean;
}

export interface LogBatch {
  batch_id: string;
  log_ids: string[];
  analyzed_at: string;
  risk_score: RiskLevel;
  summary: string;
  recommended_action: string;
  abuseipdb_confidence: number;
  top_ip: string;
}

export interface IncidentComment {
  author: string;
  role: AppRole | "SYSTEM";
  body: string;
  created_at: string;
}

export interface Incident {
  id: string;
  risk_score: RiskLevel;
  status: IncidentStatus;
  ai_summary: string;
  recommended_action: string;
  abuseipdb_confidence: number;
  top_ip: string;
  country: string;
  detected_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
  batch_ref: string;
  comments: IncidentComment[];
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  user_id: string; // user id or "SYSTEM"
  action_type: string;
  details: string;
}

export interface DashboardSummary {
  logs_analyzed_today: number;
  active_threats: Record<RiskLevel, number>;
  last_scan_time: string | null;
  critical_incidents: number;
  flagged_logs: number;
}

export interface ScanResult {
  logs_fetched: number;
  analyzed: number;
  new_alerts: number;
  executed_at: string;
}

export interface NLQueryResult {
  query: string;
  interpretation: string;
  filters_applied: Record<string, string>;
  matched_incident_ids: string[];
  matched_log_ids: string[];
}

export interface SchedulerSettings {
  enabled: boolean;
  cron_hour_utc: number;
  timezone: string;
  slack_webhook_set: boolean;
  discord_webhook_set: boolean;
  gemini_model: string;
  abuseipdb_enabled: boolean;
}
