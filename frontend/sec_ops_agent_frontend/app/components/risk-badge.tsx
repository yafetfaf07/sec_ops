import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "cn";
import type { RiskLevel } from "~/lib/types";

const riskBadgeVariants = cva(
  "inline-flex h-5 w-fit shrink-0 items-center gap-1.5 rounded-4xl border border-transparent px-2 text-xs font-medium whitespace-nowrap tabular-nums",
  {
    variants: {
      risk: {
        Low: "bg-risk-low-soft text-risk-low",
        Medium: "bg-risk-medium-soft text-risk-medium",
        High: "bg-risk-high-soft text-risk-high",
        Critical: "bg-risk-critical-soft text-risk-critical",
      },
    },
    defaultVariants: { risk: "Low" },
  },
);

export function RiskBadge({
  risk,
  className,
  showLabel = true,
}: { risk: RiskLevel; className?: string; showLabel?: boolean } & VariantProps<
  typeof riskBadgeVariants
>) {
  return (
    <span
      className={cn(riskBadgeVariants({ risk }), className)}
      aria-label={`Risk level: ${risk}`}
    >
      <span
        aria-hidden="true"
        className="size-1.5 rounded-full bg-current"
      />
      {showLabel ? risk : null}
    </span>
  );
}

export { riskBadgeVariants };
