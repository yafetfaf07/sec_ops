import {
  InfoIcon,
  ShieldAlertIcon,
  SparklesIcon,
  TriangleAlertIcon,
} from "lucide-react";
import type { Incident } from "~/lib/types";
import { formatDateTime, relativeTime } from "~/lib/format";
import { RiskBadge } from "~/components/risk-badge";
import { StatusBadge } from "~/components/status-badge";
import { IncidentActions } from "~/components/incident-actions";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "~/components/ui/dialog";
import { Progress } from "~/components/ui/progress";
import { Separator } from "~/components/ui/separator";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-right font-medium tabular-nums">{children}</dd>
    </div>
  );
}

export function IncidentDetailDialog({
  incident,
  open,
  onOpenChange,
}: {
  incident: Incident | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  if (!incident) return null;
  const elevated = incident.abuseipdb_confidence > 50;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <DialogTitle className="tabular-nums">{incident.id}</DialogTitle>
            <RiskBadge risk={incident.risk_score} />
          </div>
          <DialogDescription className="tabular-nums">
            Detected {relativeTime(incident.detected_at)} ·{" "}
            {formatDateTime(incident.detected_at)}
          </DialogDescription>
        </DialogHeader>

        <dl className="flex flex-col gap-2">
          <Field label="Status">
            <StatusBadge status={incident.status} />
          </Field>
          <Field label="Origin country">{incident.country}</Field>
          <Field label="Top IP">{incident.top_ip}</Field>
          <Field label="Log batch">{incident.batch_ref}</Field>
        </dl>

        <Separator />

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-medium">
              <SparklesIcon className="size-4 text-muted-foreground" aria-hidden />
              AI summary
            </div>
          </div>
          <p className="text-sm text-muted-foreground text-pretty">
            {incident.ai_summary}
          </p>

          <div className="rounded-lg bg-muted/50 p-3">
            <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
              <InfoIcon className="size-3.5" aria-hidden />
              Recommended action
            </div>
            <p className="mt-1 text-sm text-foreground text-pretty">
              {incident.recommended_action}
            </p>
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2 font-medium">
              <ShieldAlertIcon
                className="size-4 text-muted-foreground"
                aria-hidden
              />
              AbuseIPDB confidence
            </span>
            <span className="font-medium tabular-nums">
              {incident.abuseipdb_confidence}%
            </span>
          </div>
          <Progress value={incident.abuseipdb_confidence} />
          {elevated ? (
            <p className="flex items-center gap-1.5 text-xs text-risk-critical">
              <TriangleAlertIcon className="size-3.5" aria-hidden />
              Score above 50% — incident elevated to Critical.
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">
              Below the 50% elevation threshold.
            </p>
          )}
        </div>

        {incident.comments.length > 0 ? (
          <>
            <Separator />
            <div className="space-y-2">
              <p className="text-sm font-medium">Resolution notes</p>
              <ul className="flex flex-col gap-2">
                {incident.comments.map((c, idx) => (
                  <li
                    key={idx}
                    className="rounded-lg bg-muted/50 p-3 text-sm"
                  >
                    <p className="text-foreground text-pretty">{c.body}</p>
                    <p className="mt-1 text-xs text-muted-foreground tabular-nums">
                      {c.author} · {relativeTime(c.created_at)}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          </>
        ) : null}

        <IncidentActions incident={incident} size="default" />
      </DialogContent>
    </Dialog>
  );
}
