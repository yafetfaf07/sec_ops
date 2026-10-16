import type { ReactNode } from "react";
import { ArrowDownIcon, ArrowUpIcon, ChevronsUpDownIcon } from "lucide-react";
import { cn } from "cn";
import { TableHead } from "~/components/ui/table";
import { IconSwap } from "~/components/icon-swap";

export function SortHeader({
  label,
  active,
  dir,
  onClick,
  className,
  align = "left",
}: {
  label: ReactNode;
  active: boolean;
  dir: "asc" | "desc";
  onClick: () => void;
  className?: string;
  align?: "left" | "right";
}) {
  const ariaSort = active
    ? dir === "asc"
      ? "ascending"
      : "descending"
    : "none";

  return (
    <TableHead className={className} aria-sort={ariaSort}>
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "group -mx-1 inline-flex items-center gap-1 rounded-md px-1 py-0.5 outline-none transition-colors duration-150 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50",
          align === "right" && "flex-row-reverse",
          active ? "text-foreground" : "text-muted-foreground",
        )}
      >
        {label}
        <IconSwap
          show={active}
          a={dir === "asc" ? ArrowUpIcon : ArrowDownIcon}
          b={ChevronsUpDownIcon}
          iconClassName="size-3.5"
        />
      </button>
    </TableHead>
  );
}
