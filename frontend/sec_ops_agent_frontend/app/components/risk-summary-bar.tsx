import { cn } from "cn";
import type { RiskLevel } from "~/lib/types";

const SEGMENTS: { risk: RiskLevel; bar: string; dot: string }[] = [
  { risk: "Critical", bar: "bg-risk-critical", dot: "bg-risk-critical" },
  { risk: "High", bar: "bg-risk-high", dot: "bg-risk-high" },
  { risk: "Medium", bar: "bg-risk-medium", dot: "bg-risk-medium" },
  { risk: "Low", bar: "bg-risk-low", dot: "bg-risk-low" },
];

export function RiskSummaryBar({
  counts,
  className,
}: {
  counts: Record<RiskLevel, number>;
  className?: string;
}) {
  const total = SEGMENTS.reduce((sum, s) => sum + counts[s.risk], 0);

  return (
    <div className={cn("space-y-3", className)}>
      <div
        className="flex h-2 w-full overflow-hidden rounded-full bg-muted"
        role="img"
        aria-label={SEGMENTS.map((s) => `${s.risk}: ${counts[s.risk]}`).join(
          ", ",
        )}
      >
        {total === 0 ? null : (
          SEGMENTS.filter((s) => counts[s.risk] > 0).map((s) => (
            <div
              key={s.risk}
              className={cn(
                "h-full transition-[flex-grow] duration-300 ease-[var(--ease-out-quint)]",
                s.bar,
              )}
              style={{ flexGrow: counts[s.risk] }}
            />
          ))
        )}
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        {SEGMENTS.map((s) => (
          <div key={s.risk} className="flex items-center gap-2">
            <span
              className={cn("size-2 shrink-0 rounded-full", s.dot)}
              aria-hidden="true"
            />
            <dt className="text-xs text-muted-foreground">{s.risk}</dt>
            <dd className="ml-auto text-sm font-medium tabular-nums">
              {counts[s.risk]}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
