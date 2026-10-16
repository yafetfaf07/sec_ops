import { useState } from "react";
import type { Route } from "./+types/logs";
import { InfoIcon, LockIcon, SearchIcon, ScrollTextIcon } from "lucide-react";
import { useLogCountries, useLogs } from "~/lib/queries";
import { formatDateTime } from "~/lib/format";
import { useDebounced } from "~/hooks/use-debounced";
import { PageHeader } from "~/components/page-header";
import { ActionBadge } from "~/components/action-badge";
import { EmptyState } from "~/components/empty-state";
import { Card, CardContent, CardHeader, CardTitle } from "~/components/ui/card";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { Label } from "~/components/ui/label";
import { Skeleton } from "~/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "~/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "~/components/ui/table";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Logs · SecOps Agent" }];
}

const ACTIONS = ["All", "Login Success", "Login Failed", "Privilege Escalation"];
const PAGE_SIZE = 12;

export default function Logs() {
  const [action, setAction] = useState("All");
  const [country, setCountry] = useState("All");
  const [searchInput, setSearchInput] = useState("");
  const [page, setPage] = useState(1);

  const search = useDebounced(searchInput, 300);
  const countries = useLogCountries();

  const query = useLogs({
    action,
    country,
    search,
    page,
    pageSize: PAGE_SIZE,
  });

  const total = query.data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const resetPage = () => setPage(1);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Raw Logs"
        description="Ingested login and access events. Raw logs are immutable and cannot be deleted."
      />

      <Card className="gap-0">
        <CardHeader className="border-b">
          <CardTitle>Access events</CardTitle>
          <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="grid gap-1.5 lg:col-span-2">
              <Label htmlFor="log-search">Search</Label>
              <div className="relative">
                <SearchIcon
                  className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  id="log-search"
                  value={searchInput}
                  onChange={(e) => {
                    setSearchInput(e.target.value);
                    resetPage();
                  }}
                  placeholder="User ID, IP address or Log ID"
                  className="pl-8"
                />
              </div>
            </div>

            <div className="grid gap-1.5">
              <Label htmlFor="log-action">Action</Label>
              <Select
                value={action}
                onValueChange={(v) => {
                  setAction(v as string);
                  resetPage();
                }}
              >
                <SelectTrigger id="log-action" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-1.5">
              <Label htmlFor="log-country">Country</Label>
              <Select
                value={country}
                onValueChange={(v) => {
                  setCountry(v as string);
                  resetPage();
                }}
              >
                <SelectTrigger id="log-country" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="All">All</SelectItem>
                  {(countries.data ?? []).map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>

        <CardContent className="px-0">
          {query.isLoading ? (
            <TableSkeleton />
          ) : (query.data?.rows.length ?? 0) === 0 ? (
            <EmptyState
              icon={ScrollTextIcon}
              title="No logs match"
              description="Adjust the filters or search terms to see more events."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Timestamp</TableHead>
                  <TableHead>Log ID</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>IP address</TableHead>
                  <TableHead className="hidden md:table-cell">
                    Location
                  </TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="hidden lg:table-cell">
                    User agent
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {query.data?.rows.map((log) => (
                  <TableRow key={log.log_id}>
                    <TableCell className="pl-4 text-muted-foreground tabular-nums">
                      {formatDateTime(log.timestamp)}
                    </TableCell>
                    <TableCell className="font-mono text-xs tabular-nums text-muted-foreground">
                      {log.log_id}
                    </TableCell>
                    <TableCell className="font-medium">{log.user_id}</TableCell>
                    <TableCell className="tabular-nums">
                      {log.ip_address}
                    </TableCell>
                    <TableCell className="hidden md:table-cell text-muted-foreground">
                      {log.city}, {log.country}
                    </TableCell>
                    <TableCell>
                      <ActionBadge action={log.action} />
                    </TableCell>
                    <TableCell className="hidden max-w-xs lg:table-cell">
                      <span className="line-clamp-1 text-xs text-muted-foreground">
                        {log.user_agent}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <div className="flex items-center justify-between gap-3 border-t px-4 py-3">
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <LockIcon className="size-3.5" aria-hidden />
              Immutable —{" "}
              <span className="tabular-nums">{total}</span> events
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <span className="text-xs text-muted-foreground tabular-nums">
                Page {page} of {pageCount}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= pageCount}
                onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
              >
                Next
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <InfoIcon className="size-3.5 shrink-0" aria-hidden />
        Deletion is disabled by design to preserve audit integrity.
      </p>
    </div>
  );
}

function TableSkeleton() {
  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="pl-4">Timestamp</TableHead>
          <TableHead>Log ID</TableHead>
          <TableHead>User</TableHead>
          <TableHead>IP address</TableHead>
          <TableHead className="hidden md:table-cell">Location</TableHead>
          <TableHead>Action</TableHead>
          <TableHead className="hidden lg:table-cell">User agent</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {Array.from({ length: 8 }).map((_, i) => (
          <TableRow key={i}>
            <TableCell className="pl-4">
              <Skeleton className="h-4 w-28" />
            </TableCell>
            <TableCell>
              <Skeleton className="h-4 w-16" />
            </TableCell>
            <TableCell>
              <Skeleton className="h-4 w-20" />
            </TableCell>
            <TableCell>
              <Skeleton className="h-4 w-28" />
            </TableCell>
            <TableCell className="hidden md:table-cell">
              <Skeleton className="h-4 w-32" />
            </TableCell>
            <TableCell>
              <Skeleton className="h-5 w-28 rounded-4xl" />
            </TableCell>
            <TableCell className="hidden lg:table-cell">
              <Skeleton className="h-4 w-40" />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
