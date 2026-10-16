import { USE_MOCK, http } from "./client";
import * as mock from "~/lib/mock/handlers";
import type {
  AuditEntry,
  AuthUser,
  DashboardSummary,
  Incident,
  NLQueryResult,
  SchedulerSettings,
} from "~/lib/types";

async function call<T>(
  mockFn: () => Promise<T>,
  real: () => Promise<T>,
): Promise<T> {
  if (USE_MOCK) return mockFn();
  return real();
}

interface LoginResponse {
  access_token: string;
  user: AuthUser;
}

export const api = {
  // --- Auth -----------------------------------------------------------
  // The backend takes the acting identity from the Bearer JWT / refresh
  // cookie on every mutating call below; none of them send an `actor` field
  // (the Go handlers ignore it anyway — see PLAN.md §4.2).
  login: (email: string, password: string): Promise<LoginResponse> =>
    call(
      () => mock.login(email, password),
      async () =>
        (await http.post("/api/v1/auth/login", { email, password })).data,
    ),

  me: (): Promise<AuthUser> =>
    call(
      () => mock.me(),
      async () => (await http.get("/api/v1/auth/me")).data,
    ),

  refresh: (): Promise<LoginResponse> =>
    call(
      () => mock.refresh(),
      async () => (await http.post("/api/v1/auth/refresh")).data,
    ),

  logout: (): Promise<void> =>
    call(
      () => mock.logout(),
      async () => {
        await http.post("/api/v1/auth/logout");
      },
    ),

  // --- Dashboard --------------------------------------------------------
  getDashboardSummary: (): Promise<DashboardSummary> =>
    call(
      () => mock.getDashboardSummary(),
      async () => (await http.get("/api/v1/dashboard/summary")).data,
    ),

  // --- Incidents ----------------------------------------------------------
  getIncidents: (q: mock.IncidentQuery = {}): Promise<Incident[]> =>
    call(
      () => mock.getIncidents(q),
      async () => (await http.get("/api/v1/incidents", { params: q })).data,
    ),

  getIncidentById: (id: string): Promise<Incident> =>
    call(
      () => mock.getIncidentById(id),
      async () => (await http.get(`/api/v1/incidents/${id}`)).data,
    ),

  acknowledgeIncident: (id: string): Promise<Incident> =>
    call(
      () => mock.acknowledgeIncident(id),
      async () =>
        (await http.post(`/api/v1/incidents/${id}/acknowledge`)).data,
    ),

  resolveIncident: (id: string, comment: string): Promise<Incident> =>
    call(
      () => mock.resolveIncident(id, comment),
      async () =>
        (await http.post(`/api/v1/incidents/${id}/resolve`, { comment })).data,
    ),

  // --- Logs ---------------------------------------------------------------
  getLogs: (q: mock.LogQuery = {}): Promise<mock.LogPage> =>
    call(
      () => mock.getLogs(q),
      async () => (await http.get("/api/v1/logs", { params: q })).data,
    ),

  getLogCountries: (): Promise<string[]> =>
    call(
      () => mock.getLogCountries(),
      async () => (await http.get("/api/v1/logs/countries")).data,
    ),

  // --- Audit ----------------------------------------------------------
  getAuditLog: (): Promise<AuditEntry[]> =>
    call(
      () => mock.getAuditLog(),
      async () => (await http.get("/api/v1/audit")).data,
    ),

  // --- Scan -----------------------------------------------------------
  // POST /scan/daily is reserved for Cloud Scheduler's OIDC token or an
  // admin JWT with the scheduled-trigger semantics; the dashboard's manual
  // "Run scan" button hits /scan/run instead.
  runScan: () =>
    call(
      () => mock.runScan(),
      async () => (await http.post("/api/v1/scan/run")).data,
    ),

  // --- Natural language query ------------------------------------------
  runNaturalLanguageQuery: (query: string): Promise<NLQueryResult> =>
    call(
      () => mock.runNaturalLanguageQuery(query),
      async () => (await http.post("/api/v1/query", { query })).data,
    ),

  // --- Settings ---------------------------------------------------------
  getSettings: (): Promise<SchedulerSettings> =>
    call(
      () => mock.getSettings(),
      async () => (await http.get("/api/v1/settings")).data,
    ),

  updateSettings: (
    patch: Partial<SchedulerSettings>,
  ): Promise<SchedulerSettings> =>
    call(
      () => mock.updateSettings(patch),
      async () => (await http.put("/api/v1/settings", { patch })).data,
    ),
};
