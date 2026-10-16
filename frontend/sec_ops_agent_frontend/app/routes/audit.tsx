import type { Route } from "./+types/audit";
import { BotIcon, LockIcon, ShieldCheckIcon } from "lucide-react";
import { useAuditLog } from "~/lib/queries";
import { formatDateTime, relativeTime } from "~/lib/format";
import { PageHeader } from "~/components/page-header";
import { EmptyState } from "~/components/empty-state";
import { Card, CardContent, CardHeader, CardTitle } from "~/components/ui/card";
import { Badge } from "~/components/ui/badge";
import { Skeleton } from "~/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "~/components/ui/table";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Audit Log · SecOps Agent" }];
}

export default function Audit() {
  const { data, isLoading } = useAuditLog();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        description="Immutable record of every AI analysis, alert and incident action."
      />

      <Card className="gap-0">
        <CardHeader className="border-b">
          <CardTitle>Activity trail</CardTitle>
        </CardHeader>
        <CardContent className="px-0">
          {isLoading ? (
            <TableSkeleton />
          ) : (data?.length ?? 0) === 0 ? (
            <EmptyState
              icon={ShieldCheckIcon}
              title="No activity yet"
              description="Audit entries appear as the system runs scans, sends alerts and resolves incidents."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Timestamp</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="hidden md:table-cell">
                    Details
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.map((entry) => {
                  const isSystem = entry.user_id === "SYSTEM";
                  return (
                    <TableRow key={entry.id}>
                      <TableCell className="pl-4 whitespace-nowrap text-muted-foreground tabular-nums">
                        <span className="block">
                          {formatDateTime(entry.timestamp)}
                        </span>
                        <span className="block text-xs">
                          {relativeTime(entry.timestamp)}
                        </span>
                      </TableCell>
                      <TableCell>
                        {isSystem ? (
                          <Badge variant="outline" className="gap-1">
                            <BotIcon className="size-3" aria-hidden />
                            SYSTEM
                          </Badge>
                        ) : (
                          <span className="font-medium">{entry.user_id}</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-xs text-muted-foreground">
                          {entry.action_type}
                        </span>
                      </TableCell>
                      <TableCell className="hidden max-w-lg md:table-cell">
                        <span className="text-sm text-muted-foreground">
                          {entry.details}
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}

          <div className="flex items-center gap-1.5 border-t px-4 py-3 text-xs text-muted-foreground">
            <LockIcon className="size-3.5" aria-hidden />
            Entries are append-only and cannot be edited or deleted.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function TableSkeleton() {
  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="pl-4">Timestamp</TableHead>
          <TableHead>Actor</TableHead>
          <TableHead>Action</TableHead>
          <TableHead className="hidden md:table-cell">Details</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {Array.from({ length: 8 }).map((_, i) => (
          <TableRow key={i}>
            <TableCell className="pl-4">
              <Skeleton className="h-8 w-28" />
            </TableCell>
            <TableCell>
              <Skeleton className="h-5 w-20 rounded-4xl" />
            </TableCell>
            <TableCell>
              <Skeleton className="h-4 w-40" />
            </TableCell>
            <TableCell className="hidden md:table-cell">
              <Skeleton className="h-4 w-64" />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
