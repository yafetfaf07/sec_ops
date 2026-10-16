import { toast } from "sonner";
import { MenuIcon, RefreshCwIcon, ScanLineIcon } from "lucide-react";
import { useRunScan } from "~/lib/queries";
import { useIsAdmin } from "~/stores/auth";
import { relativeTime } from "~/lib/format";
import { Button } from "~/components/ui/button";
import { Sheet, SheetContent, SheetTitle } from "~/components/ui/sheet";
import { UserMenu } from "~/components/user-menu";
import { AppSidebar } from "~/components/app-sidebar";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "~/components/ui/tooltip";
import { useState } from "react";

export function Topbar({
  lastScan,
  openCount,
}: {
  lastScan: string | null;
  openCount: number;
}) {
  const [navOpen, setNavOpen] = useState(false);
  const runScan = useRunScan();
  const isAdmin = useIsAdmin();

  const onScan = () => {
    runScan.mutate(undefined, {
      onSuccess: (r) =>
        toast.success("Scan complete", {
          description: `Analyzed ${r.analyzed} logs · ${r.new_alerts} new alerts.`,
        }),
      onError: () => toast.error("Scan failed. Please retry."),
    });
  };

  const scanButton = (
    <Button
      variant="outline"
      size="sm"
      onClick={onScan}
      disabled={runScan.isPending || !isAdmin}
    >
      <RefreshCwIcon className={runScan.isPending ? "animate-spin" : undefined} aria-hidden />
      <span className="hidden sm:inline">
        {runScan.isPending ? "Scanning…" : "Run scan"}
      </span>
      <span className="sr-only sm:hidden">Run scan</span>
    </Button>
  );

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <Sheet open={navOpen} onOpenChange={setNavOpen}>
        <Button
          variant="ghost"
          size="icon-sm"
          className="lg:hidden"
          onClick={() => setNavOpen(true)}
          aria-label="Open navigation"
        >
          <MenuIcon aria-hidden />
        </Button>
        <SheetContent side="left" className="w-64 bg-sidebar p-0 text-sidebar-foreground">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <AppSidebar openCount={openCount} onNavigate={() => setNavOpen(false)} />
        </SheetContent>
      </Sheet>

      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <ScanLineIcon className="size-4" aria-hidden />
        <span className="hidden sm:inline">Last scan</span>
        <span className="tabular-nums text-foreground">
          {lastScan ? relativeTime(lastScan) : "—"}
        </span>
      </div>

      <div className="ml-auto flex items-center gap-2">
        {isAdmin ? (
          scanButton
        ) : (
          <Tooltip>
            <TooltipTrigger render={<span tabIndex={0} />}>
              {scanButton}
            </TooltipTrigger>
            <TooltipContent>
              Only the Admin role can trigger scans.
            </TooltipContent>
          </Tooltip>
        )}
        <UserMenu />
      </div>
    </header>
  );
}
