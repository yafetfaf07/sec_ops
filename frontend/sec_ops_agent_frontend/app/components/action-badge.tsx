import { cva } from "class-variance-authority";
import { cn } from "cn";
import type { LogAction } from "~/lib/types";

const actionVariants = cva(
  "inline-flex h-5 w-fit shrink-0 items-center rounded-4xl border border-transparent px-2 text-xs font-medium whitespace-nowrap",
  {
    variants: {
      action: {
        "Login Success": "bg-foreground/8 text-foreground/80",
        "Login Failed": "bg-risk-medium-soft text-risk-medium",
        "Privilege Escalation": "bg-risk-critical-soft text-risk-critical",
      },
    },
  },
);

export function ActionBadge({
  action,
  className,
}: {
  action: LogAction;
  className?: string;
}) {
  return (
    <span className={cn(actionVariants({ action }), className)}>{action}</span>
  );
}
