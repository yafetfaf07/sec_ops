import type { ReactNode } from "react";
import { ShieldXIcon } from "lucide-react";
import { useAuthUser } from "~/stores/auth";
import { Card, CardContent } from "~/components/ui/card";

export function RequireAdmin({ children }: { children: ReactNode }) {
  const user = useAuthUser();

  if (user?.role !== "admin") {
    return (
      <Card className="mx-auto mt-10 max-w-md">
        <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
          <div className="flex size-10 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
            <ShieldXIcon className="size-5" aria-hidden />
          </div>
          <div className="space-y-1">
            <h2 className="font-heading text-base font-medium">
              Admins only
            </h2>
            <p className="text-sm text-muted-foreground text-pretty">
              Configuring scheduler triggers and API keys requires the Admin
              role. Sign in with an admin account to continue.
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return <>{children}</>;
}
