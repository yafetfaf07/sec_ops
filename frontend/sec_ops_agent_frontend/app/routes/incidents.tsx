import { useMemo, useState } from "react";
import type { Route } from "./+types/incidents";
import { InboxIcon, SparklesIcon, XIcon } from "lucide-react";
import { useIncidents } from "~/lib/queries";
import { RISK_ORDER, relativeTime } from "~/lib/format";
import { useCommandStore } from "~/stores/command";
import type { IncidentStatus } from "~/lib/types";
import { PageHeader } from "~/components/page-header";
import { RiskBadge } from "~/components/risk-badge";
import { StatusBadge } from "~/components/status-badge";
import { SortHeader } from "~/components/sort-header";
import { EmptyState } from "~/components/empty-state";
import { IncidentDetailDialog } from "~/components/incident-detail-dialog";
import { Badge } from "~/components/ui/badge";
import { Button } from "~/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "~/components/ui/card";
import { Skeleton } from "~/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "~/components/ui/table";
import { cn } from "cn";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Incidents · SecOps Agent" }];
}

const TABS: (IncidentStatus | "All")[] = [
  "Open",
  "Acknowledged",
  "Resolved",
  "All",
];

type SortBy = "date" | "risk";

export default function Incidents() {
  const [status, setStatus] = useState<IncidentStatus | "All">("Open");
  const [sortBy, setSortBy] = useState<SortBy>("date");
  const [dir, setDir] = useState<"asc" | "desc">("desc");
  const [selected, setSelected] = useState<string | null>(null);

  const messages = useCommandStore((s) => s.messages);
  const clear = useCommandStore((s) => s.clear);
  const latestResult = useMemo(
    () => [...messages].reverse().find((m) => m.result)?.result ?? null,
    [messages],
  );

  const query = useIncidents({
    status,
    sort: sortBy === "risk" ? "risk_score" : "detected_at",
    dir,
  });

  const rows = useMemo(() => {
    const all = query.data ?? [];
    if (!latestResult) return all;
    return all.filter((i) => latestResult.matched_incident_ids.includes(i.id));
  }, [query.data, latestResult]);

  const selectedIncident = useMemo(
    () => (query.data ?? []).find((i) => i.id === selected) ?? null,
    [query.data, selected],
  );

  const toggleSort = (next: SortBy) => {
    if (sortBy === next) setDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortBy(next);
      setDir("desc");
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incidents"
        description="AI-triaged security incidents. Acknowledge to claim, resolve to close."
      />

      <Card className="gap-0">
        <CardHeader className="flex-col gap-3 border-b sm:flex-row sm:items-center sm:justify-between">
          <div
            className="inline-flex items-center gap-1 rounded-lg bg-muted p-[3px]"
            role="group"
            aria-label="Filter incidents by status"
          >
            {TABS.map((t) => (
              <button
                key={t}
                type="button"
                aria-pressed={status === t}
                onClick={() => setStatus(t)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-sm font-medium outline-none transition-colors duration-150 focus-visible:ring-2 focus-visible:ring-ring/50",
                  status === t
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {t}
              </button>
            ))}
          </div>

          {latestResult ? (
            <div className="flex items-center gap-2">
              <Badge variant="secondary" className="gap-1">
                <SparklesIcon className="size-3" aria-hidden />
                Query filter active
              </Badge>
              <Button variant="ghost" size="xs" onClick={clear}>
                <XIcon aria-hidden />
                Clear
              </Button>
            </div>
          ) : null}
        </CardHeader>

        <CardContent className="px-0">
          {query.isLoading ? (
            <TableSkeleton />
          ) : rows.length === 0 ? (
            <EmptyState
              icon={InboxIcon}
              title="No incidents here"
              description={
                latestResult
                  ? "No incidents match the active AI query filter. Clear it to see all."
                  : "Nothing matches this status filter. Try another tab."
              }
              action={
                latestResult ? (
                  <Button variant="outline" size="sm" onClick={clear}>
                    Clear filter
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Incident</TableHead>
                  <SortHeader
                    label="Risk"
                    active={sortBy === "risk"}
                    dir={dir}
                    onClick={() => toggleSort("risk")}
                  />
                  <TableHead className="hidden md:table-cell">
                    AI summary
                  </TableHead>
                  <TableHead className="hidden sm:table-cell">
                    Country
                  </TableHead>
                  <TableHead>Status</TableHead>
                  <SortHeader
                    label="Detected"
                    active={sortBy === "date"}
                    dir={dir}
                    onClick={() => toggleSort("date")}
                  />
                  <TableHead className="pr-4 text-right">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((i) => (
                  <TableRow
                    key={i.id}
                    onClick={() => setSelected(i.id)}
                    className="cursor-pointer"
                  >
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
                    <TableCell className="text-muted-foreground tabular-nums">
                      {relativeTime(i.detected_at)}
                    </TableCell>
                    <TableCell className="pr-4 text-right">
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelected(i.id);
                        }}
                      >
                        Review
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <IncidentDetailDialog
        incident={selectedIncident}
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      />
    </div>
  );
}

function TableSkeleton() {
  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="pl-4">Incident</TableHead>
          <TableHead>Risk</TableHead>
          <TableHead className="hidden md:table-cell">AI summary</TableHead>
          <TableHead className="hidden sm:table-cell">Country</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Detected</TableHead>
          <TableHead className="pr-4" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {Array.from({ length: 6 }).map((_, i) => (
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
            <TableCell>
              <Skeleton className="h-4 w-16" />
            </TableCell>
            <TableCell className="pr-4">
              <Skeleton className="ml-auto h-6 w-14" />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
