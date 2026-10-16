import type { ComponentType, ReactNode } from "react";
import { cn } from "cn";
import { Card, CardContent } from "~/components/ui/card";
import { Skeleton } from "~/components/ui/skeleton";

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  tone = "neutral",
  loading = false,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon: ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  tone?: "neutral" | "low" | "medium" | "high" | "critical";
  loading?: boolean;
  className?: string;
}) {
  const toneClasses: Record<string, string> = {
    neutral: "bg-muted text-muted-foreground",
    low: "bg-risk-low-soft text-risk-low",
    medium: "bg-risk-medium-soft text-risk-medium",
    high: "bg-risk-high-soft text-risk-high",
    critical: "bg-risk-critical-soft text-risk-critical",
  };

  return (
    <Card className={cn("justify-between gap-3", className)} size="sm">
      <CardContent className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">{label}</p>
          {loading ? (
            <Skeleton className="h-7 w-16" />
          ) : (
            <p className="font-heading text-2xl font-medium tabular-nums tracking-tight">
              {value}
            </p>
          )}
          {hint && !loading ? (
            <p className="text-xs text-muted-foreground">{hint}</p>
          ) : null}
        </div>
        <div
          className={cn(
            "flex size-8 shrink-0 items-center justify-center rounded-lg",
            toneClasses[tone],
          )}
        >
          <Icon className="size-4" aria-hidden />
        </div>
      </CardContent>
    </Card>
  );
}
