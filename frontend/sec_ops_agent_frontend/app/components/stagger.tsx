import type { ReactNode } from "react";
import { cn } from "cn";

/**
 * Staged entrance for infrequent first loads (dashboard, detail views).
 * Combines opacity 0→1, translateY 12px→0 and blur 4px→0 over 400ms,
 * staggered ~100ms per item. Not for high-frequency interactions.
 */
export function StaggerItem({
  index = 0,
  children,
  className,
}: {
  index?: number;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "animate-in fade-in-0 slide-in-from-bottom-3 blur-in-[4px] fill-mode-both duration-[400ms] ease-out",
        className,
      )}
      style={{ animationDelay: `${index * 100}ms` }}
    >
      {children}
    </div>
  );
}
