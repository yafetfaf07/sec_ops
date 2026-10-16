import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "~/lib/api/endpoints";
import type { SchedulerSettings } from "~/lib/types";
import type { IncidentQuery, LogQuery } from "~/lib/mock/handlers";

export const queryKeys = {
  dashboard: ["dashboard"] as const,
  incidents: (q?: IncidentQuery) => ["incidents", q ?? {}] as const,
  logs: (q?: LogQuery) => ["logs", q ?? {}] as const,
  logCountries: ["log-countries"] as const,
  audit: ["audit"] as const,
  settings: ["settings"] as const,
};

export function useDashboardSummary(opts: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: queryKeys.dashboard,
    queryFn: () => api.getDashboardSummary(),
    refetchInterval: 30_000,
    enabled: opts.enabled ?? true,
  });
}

export function useIncidents(q: IncidentQuery = {}) {
  return useQuery({
    queryKey: queryKeys.incidents(q),
    queryFn: () => api.getIncidents(q),
  });
}

export function useLogs(q: LogQuery = {}) {
  return useQuery({
    queryKey: queryKeys.logs(q),
    queryFn: () => api.getLogs(q),
  });
}

export function useLogCountries() {
  return useQuery({
    queryKey: queryKeys.logCountries,
    queryFn: () => api.getLogCountries(),
    staleTime: Infinity,
  });
}

export function useAuditLog() {
  return useQuery({
    queryKey: queryKeys.audit,
    queryFn: () => api.getAuditLog(),
  });
}

export function useSettings() {
  return useQuery({
    queryKey: queryKeys.settings,
    queryFn: () => api.getSettings(),
  });
}

function useInvalidateAll() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["incidents"] });
    void qc.invalidateQueries({ queryKey: queryKeys.dashboard });
    void qc.invalidateQueries({ queryKey: queryKeys.audit });
  };
}

export function useAcknowledgeIncident() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: ({ id }: { id: string }) => api.acknowledgeIncident(id),
    onSuccess: invalidate,
  });
}

export function useResolveIncident() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: ({ id, comment }: { id: string; comment: string }) =>
      api.resolveIncident(id, comment),
    onSuccess: invalidate,
  });
}

export function useRunScan() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: () => api.runScan(),
    onSuccess: invalidate,
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: Partial<SchedulerSettings>) =>
      api.updateSettings(patch),
    onSuccess: (data) => {
      qc.setQueryData(queryKeys.settings, data);
      void qc.invalidateQueries({ queryKey: queryKeys.audit });
    },
  });
}
