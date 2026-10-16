import {
  ChevronDownIcon,
  EyeIcon,
  LogOutIcon,
  ShieldCheckIcon,
  ShieldIcon,
} from "lucide-react";
import { useAuthUser } from "~/stores/auth";
import { useLogout } from "~/lib/auth-hooks";
import type { AppRole } from "~/lib/types";
import { Button } from "~/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "~/components/ui/dropdown-menu";

const ROLE_ICON: Record<AppRole, typeof ShieldIcon> = {
  admin: ShieldCheckIcon,
  analyst: ShieldIcon,
  viewer: EyeIcon,
};

const ROLE_LABEL: Record<AppRole, string> = {
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Read-Only Viewer",
};

export function UserMenu() {
  const user = useAuthUser();
  const logout = useLogout();

  if (!user) return null;
  const CurrentIcon = ROLE_ICON[user.role];

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="outline" size="sm" className="gap-2">
            <CurrentIcon className="size-4 text-muted-foreground" aria-hidden />
            <span className="hidden sm:inline">{user.name}</span>
            <ChevronDownIcon
              className="size-3.5 text-muted-foreground"
              aria-hidden
            />
          </Button>
        }
      />
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="grid gap-0.5">
          <span className="font-medium text-foreground">{user.name}</span>
          <span className="text-xs text-muted-foreground">{user.email}</span>
          <span className="text-xs text-muted-foreground">
            {ROLE_LABEL[user.role]}
          </span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => logout.mutate()}
          disabled={logout.isPending}
          className="text-destructive"
        >
          <LogOutIcon className="size-4" aria-hidden />
          {logout.isPending ? "Signing out…" : "Sign out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
