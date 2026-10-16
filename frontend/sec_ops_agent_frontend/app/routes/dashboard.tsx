import { useMemo, useState } from "react";
import type { Route } from "./+types/dashboard";
import {
  ActivityIcon,
  FlaskConicalIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  SparklesIcon,
  XIcon,
} from "lucide-react";
import { useDashboardSummary, useIncidents } from "~/lib/queries";
import { formatDateTime, RISK_ORDER, relativeTime } from "~/lib/format";
import { useCommandStore } from "~/stores/command";
import type { Incident } from "~/lib/types";
import { PageHeader } from "~/components/page-header";
import { StatCard } from "~/components/stat-card";
import { StaggerItem } from "~/components/stagger";
import { RiskSummaryBar } from "~/components/risk-summary-bar";
import { CommandInterface } from "~/components/command-interface";
import { RiskBadge } from "~/components/risk-badge";
import { StatusBadge } from "~/components/status-badge";
import { SortHeader } from "~/components/sort-header";
import { Card, CardContent, CardHeader, CardTitle } from "~/components/ui/card";
import { Badge } from "~/components/ui/badge";
import { Button } from "~/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "~/components/ui/table";
import { Skeleton } from "~/components/ui/skeleton";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Security Overview · SecOps Agent" }];
}

type SortBy = "date" | "risk";

export default function Dashboard() {
  const summary = useDashboardSummary();
  const incidents = useIncidents({ sort: "detected_at", dir: "desc" });
  const messages = useCommandStore((s) => s.messages);
  const clear = useCommandStore((s) => s.clear);

  const [sortBy, setSortBy] = useState<SortBy>("date");
  const [dir, setDir] = useState<"asc" | "desc">("desc");

  const latestResult = useMemo(
    () => [...messages].reverse().find((m) => m.result)?.result ?? null,
    [messages],
  );

  const rows = useMemo(() => {
    const all = incidents.data ?? [];
    const filtered = latestResult
      ? all.filter((i) => latestResult.matched_incident_ids.includes(i.id))
      : all;
    const sorted = [...filtered].sort((a, b) => {
      const cmp =
        sortBy === "risk"
          ? RISK_ORDER[a.risk_score] - RISK_ORDER[b.risk_score]
          : a.detected_at.localeCompare(b.detected_at);
      return dir === "asc" ? cmp : -cmp;
    });
    return sorted.slice(0, 8);
  }, [incidents.data, latestResult, sortBy, dir]);

  const toggleSort = (next: SortBy) => {
    if (sortBy === next) {
      setDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(next);
      setDir(next === "risk" ? "desc" : "desc");
    }
  };

  const threats = summary.data?.active_threats;
  const activeTotal = threats
    ? Object.values(threats).reduce((a, b) => a + b, 0)
    : 0;

  return (
    <div className="space-y-6">
      <StaggerItem index={0}>
        <PageHeader
          title="Security Overview"
          description="Real-time posture from AI-analyzed login and access events."
        />
      </StaggerItem>

      <StaggerItem index={1}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Logs analyzed today"
            value={summary.data?.logs_analyzed_today ?? 0}
            hint="Rolling 24-hour ingestion"
            icon={ActivityIcon}
            loading={summary.isLoading}
          />
          <StatCard
            label="Active threats"
            value={activeTotal}
            hint={
              threats
                ? `${threats.Critical} critical · ${threats.High} high`
                : undefined
            }
            icon={ShieldAlertIcon}
            tone={threats && threats.Critical > 0 ? "critical" : "high"}
            loading={summary.isLoading}
          />
          <StatCard
            label="Flagged logs"
            value={summary.data?.flagged_logs ?? 0}
            hint="Login Failed / Priv. Escalation"
            icon={FlaskConicalIcon}
            tone="medium"
            loading={summary.isLoading}
          />
          <StatCard
            label="Last scan"
            value={
              summary.data?.last_scan_time
                ? relativeTime(summary.data.last_scan_time)
                : "—"
            }
            hint={
              summary.data?.last_scan_time
                ? formatDateTime(summary.data.last_scan_time)
                : "Scheduler pending"
            }
            icon={RefreshCwIcon}
            loading={summary.isLoading}
          />
        </div>
      </StaggerItem>

      <StaggerItem index={2}>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Active threats by risk</CardTitle>
            </CardHeader>
            <CardContent>
              {threats ? (
                <RiskSummaryBar counts={threats} />
              ) : (
                <div className="space-y-3">
                  <Skeleton className="h-2 w-full rounded-full" />
                  <Skeleton className="h-6 w-full" />
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="gap-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <SparklesIcon
                  className="size-4 text-muted-foreground"
                  aria-hidden
                />
                Ask the SecOps agent
              </CardTitle>
            </CardHeader>
            <CardContent>
              <CommandInterface />
            </CardContent>
          </Card>
        </div>
      </StaggerItem>

      <StaggerItem index={3}>
        <Card className="gap-0">
          <CardHeader className="border-b">
            <CardTitle>Recent AI-analyzed incidents</CardTitle>
            {latestResult ? (
              <div className="flex items-center gap-2 pt-1">
                <Badge variant="secondary" className="gap-1">
                  <SparklesIcon className="size-3" aria-hidden />
                  Filtered by query
                </Badge>
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={clear}
                  className="text-muted-foreground"
                >
                  <XIcon aria-hidden />
                  Clear
                </Button>
              </div>
            ) : null}
          </CardHeader>
          <CardContent className="px-0">
            <IncidentTable
              rows={rows}
              loading={incidents.isLoading}
              sortBy={sortBy}
              dir={dir}
              onSort={toggleSort}
            />
          </CardContent>
        </Card>
      </StaggerItem>
    </div>
  );
}

function IncidentTable({
  rows,
  loading,
  sortBy,
  dir,
  onSort,
}: {
  rows: Incident[];
  loading: boolean;
  sortBy: SortBy;
  dir: "asc" | "desc";
  onSort: (s: SortBy) => void;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="pl-4">Incident</TableHead>
          <SortHeader
            label="Risk"
            active={sortBy === "risk"}
            dir={dir}
            onClick={() => onSort("risk")}
          />
          <TableHead className="hidden md:table-cell">AI summary</TableHead>
          <TableHead className="hidden sm:table-cell">Country</TableHead>
          <TableHead>Status</TableHead>
          <SortHeader
            label="Detected"
            active={sortBy === "date"}
            dir={dir}
            onClick={() => onSort("date")}
            className="pr-4"
          />
        </TableRow>
      </TableHeader>
      <TableBody>
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <TableRow key={i}>
              <TableCell className="pl-4">
                <Skeleton className="h-4 w-16" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-5 w-16 rounded-4xl" />
              </TableCell>
              <TableCell className="hidden md:table-cell">
                <Skeleton className="h-4 w-56" />
              </TableCell>
              <TableCell className="hidden sm:table-cell">
                <Skeleton className="h-4 w-20" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-5 w-24 rounded-4xl" />
              </TableCell>
              <TableCell className="pr-4">
                <Skeleton className="h-4 w-16" />
              </TableCell>
            </TableRow>
          ))
        ) : rows.length === 0 ? (
          <TableRow className="hover:bg-transparent">
            <TableCell
              colSpan={6}
              className="py-10 text-center text-sm text-muted-foreground"
            >
              No incidents match the current view.
            </TableCell>
          </TableRow>
        ) : (
          rows.map((i) => (
            <TableRow key={i.id}>
              <TableCell className="pl-4 font-medium tabular-nums">
                {i.id}
              </TableCell>
              <TableCell>
                <RiskBadge risk={i.risk_score} />
              </TableCell>
              <TableCell className="hidden max-w-md md:table-cell">
                <span className="line-clamp-1 text-muted-foreground">
                  {i.ai_summary}
                </span>
              </TableCell>
              <TableCell className="hidden sm:table-cell">
                {i.country}
              </TableCell>
              <TableCell>
                <StatusBadge status={i.status} />
              </TableCell>
              <TableCell className="pr-4 text-muted-foreground tabular-nums">
                {relativeTime(i.detected_at)}
              </TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );
}
