import { Navigate, Outlet } from "react-router";
import { LoaderCircleIcon } from "lucide-react";
import { useDashboardSummary } from "~/lib/queries";
import { useAuthStore, useIsAuthenticated } from "~/stores/auth";
import { AppSidebar } from "~/components/app-sidebar";
import { Topbar } from "~/components/topbar";

export default function AppLayout() {
  const initialized = useAuthStore((s) => s.initialized);
  const isAuthenticated = useIsAuthenticated();

  // Dashboard summary drives the open-incident badge in the sidebar; only
  // fetch it once we actually have a session (avoids a doomed 401 racing
  // the initial refresh-cookie bootstrap).
  const { data } = useDashboardSummary({ enabled: isAuthenticated });

  if (!initialized) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <LoaderCircleIcon className="size-5 animate-spin text-muted-foreground" aria-hidden />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  const openCount = data
    ? Object.values(data.active_threats).reduce((a, b) => a + b, 0)
    : 0;

  return (
    <div className="flex min-h-svh bg-background">
      <aside
        className="sticky top-0 hidden h-svh w-60 shrink-0 overflow-y-auto border-r border-sidebar-border bg-sidebar lg:block"
        aria-label="Sidebar"
      >
        <AppSidebar openCount={openCount} />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar lastScan={data?.last_scan_time ?? null} openCount={openCount} />
        <main className="mx-auto w-full max-w-screen-2xl flex-1 px-4 py-6 sm:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
