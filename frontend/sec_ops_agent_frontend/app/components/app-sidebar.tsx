import { NavLink } from "react-router";
import { ShieldIcon } from "lucide-react";
import { cn } from "cn";
import { NAV_ITEMS } from "~/lib/nav";
import { useAuthUser } from "~/stores/auth";

function NavItems({
  openCount,
  onNavigate,
}: {
  openCount: number;
  onNavigate?: () => void;
}) {
  const user = useAuthUser();

  return (
    <nav className="flex flex-col gap-0.5" aria-label="Primary">
      {NAV_ITEMS.filter((item) => !item.adminOnly || user?.role === "admin").map(
        (item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "group flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring/50",
                  isActive
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground",
                )
              }
            >
              <Icon className="size-4 shrink-0" aria-hidden />
              <span className="truncate">{item.label}</span>
              {item.to === "/incidents" && openCount > 0 ? (
                <span className="ml-auto inline-flex h-5 min-w-5 items-center justify-center rounded-4xl bg-risk-critical-soft px-1.5 text-xs font-medium text-risk-critical tabular-nums">
                  {openCount}
                </span>
              ) : null}
            </NavLink>
          );
        },
      )}
    </nav>
  );
}

export function SidebarBrand() {
  return (
    <div className="flex items-center gap-2.5 px-1.5">
      <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <ShieldIcon className="size-4.5" aria-hidden />
      </div>
      <div className="grid leading-tight">
        <span className="font-heading text-sm font-semibold">SecOps Agent</span>
        <span className="text-xs text-muted-foreground">
          AI Threat Detection
        </span>
      </div>
    </div>
  );
}

export function AppSidebar({
  openCount,
  onNavigate,
}: {
  openCount: number;
  onNavigate?: () => void;
}) {
  return (
    <div className="flex h-full flex-col gap-6 p-3">
      <div className="pt-2">
        <SidebarBrand />
      </div>
      <NavItems openCount={openCount} onNavigate={onNavigate} />
      <div className="mt-auto rounded-lg bg-sidebar-accent/50 p-3 text-xs text-muted-foreground">
        <p className="font-medium text-foreground">Free-tier deployment</p>
        <p className="mt-1 text-pretty">
          Gemini · AbuseIPDB · Slack run on documented free tiers.
        </p>
      </div>
    </div>
  );
}

export { NavItems };
