import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "cn";
import { CircleCheckIcon, CircleDotIcon, ClockIcon } from "lucide-react";
import type { IncidentStatus } from "~/lib/types";

const statusVariants = cva(
  "inline-flex h-5 w-fit shrink-0 items-center gap-1 rounded-4xl border border-transparent px-2 text-xs font-medium whitespace-nowrap",
  {
    variants: {
      status: {
        Open: "bg-foreground/8 text-foreground/80",
        Acknowledged: "bg-risk-medium-soft text-risk-medium",
        Resolved: "bg-risk-low-soft text-risk-low",
      },
    },
    defaultVariants: { status: "Open" },
  },
);

const ICONS = {
  Open: CircleDotIcon,
  Acknowledged: ClockIcon,
  Resolved: CircleCheckIcon,
} as const;

export function StatusBadge({
  status,
  className,
}: { status: IncidentStatus; className?: string }) {
  const Icon = ICONS[status];
  return (
    <span className={cn(statusVariants({ status }), className)}>
      <Icon className="size-3" aria-hidden="true" />
      {status}
    </span>
  );
}
