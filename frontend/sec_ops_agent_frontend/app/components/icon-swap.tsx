import type { ComponentType } from "react";
import { cn } from "cn";

/**
 * Cross-fades two icons in place using the exact better-ui icon-transition recipe:
 * opacity 0→1, scale 0.25→1, blur 4px→0px over 300ms cubic-bezier(0.2, 0, 0, 1).
 * The inactive icon defines layout size; the active one overlays absolutely.
 */
export function IconSwap({
  show,
  a: A,
  b: B,
  className,
  iconClassName,
}: {
  show: boolean;
  a: ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  b: ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  className?: string;
  iconClassName?: string;
}) {
  const base =
    "transition-[opacity,filter,scale] duration-300 ease-[cubic-bezier(0.2,0,0,1)]";
  const on = "scale-100 opacity-100 blur-0";
  const off = "scale-[0.25] opacity-0 blur-[4px]";

  return (
    <span
      className={cn("relative inline-flex items-center justify-center", className)}
    >
      <span
        className={cn(
          "absolute inset-0 flex items-center justify-center",
          base,
          show ? on : off,
        )}
      >
        <A className={cn("size-4", iconClassName)} aria-hidden />
      </span>
      <span className={cn(base, show ? off : on)}>
        <B className={cn("size-4", iconClassName)} aria-hidden />
      </span>
    </span>
  );
}
