import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router";
import type { Route } from "./+types/login";
import { toast } from "sonner";
import { LoaderCircleIcon, LockIcon, ShieldIcon } from "lucide-react";
import { useLogin } from "~/lib/auth-hooks";
import { useIsAuthenticated, useAuthStore } from "~/stores/auth";
import { USE_MOCK } from "~/lib/api/client";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { Label } from "~/components/ui/label";
import { Card, CardContent, CardHeader } from "~/components/ui/card";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Sign in · SecOps Agent" }];
}

export default function Login() {
  const navigate = useNavigate();
  const isAuthenticated = useIsAuthenticated();
  const initialized = useAuthStore((s) => s.initialized);
  const login = useLogin();

  const [email, setEmail] = useState(USE_MOCK ? "admin@example.com" : "");
  const [password, setPassword] = useState(USE_MOCK ? "demo" : "");

  useEffect(() => {
    if (isAuthenticated) navigate("/", { replace: true });
  }, [isAuthenticated, navigate]);

  // Wait for the one-time refresh-cookie bootstrap (app/root.tsx) to settle
  // before deciding this user is actually logged out — otherwise a page
  // reload briefly flashes the login form even with a valid session cookie.
  if (!initialized) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <LoaderCircleIcon className="size-5 animate-spin text-muted-foreground" aria-hidden />
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password) {
      toast.error("Enter your email and password.");
      return;
    }
    login.mutate(
      { email: email.trim(), password },
      {
        onSuccess: () => navigate("/", { replace: true }),
        onError: () => toast.error("Invalid email or password."),
      },
    );
  };

  return (
    <div className="flex min-h-svh items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldIcon className="size-5" aria-hidden />
          </div>
          <div>
            <h1 className="font-heading text-lg font-semibold">SecOps Agent</h1>
            <p className="text-sm text-muted-foreground">
              Sign in to view your security posture.
            </p>
          </div>
        </div>

        <Card>
          <CardHeader className="sr-only">Sign in</CardHeader>
          <CardContent>
            <form onSubmit={submit} className="grid gap-4">
              <div className="grid gap-1.5">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  disabled={login.isPending}
                  autoFocus
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  disabled={login.isPending}
                />
              </div>
              <Button type="submit" className="w-full" disabled={login.isPending}>
                {login.isPending ? (
                  <LoaderCircleIcon className="animate-spin" aria-hidden />
                ) : (
                  <LockIcon aria-hidden />
                )}
                Sign in
              </Button>
            </form>
          </CardContent>
        </Card>

        {USE_MOCK ? (
          <p className="text-center text-xs text-muted-foreground">
            Running in mock mode. Any password works; the email's local part
            (<code>admin@</code>/<code>analyst@</code>/<code>viewer@</code>)
            picks the role.
          </p>
        ) : null}
      </div>
    </div>
  );
}
