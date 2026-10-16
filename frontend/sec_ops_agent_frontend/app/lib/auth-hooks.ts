import { useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { api } from "~/lib/api/endpoints";
import { useAuthStore } from "~/stores/auth";

/**
 * Bootstraps the session once per app load: tries POST /auth/refresh (which
 * rides on the httpOnly refresh cookie set by a previous login) to mint a
 * fresh access token without the user re-entering credentials. Marks the
 * store `initialized` either way so route guards know when it's safe to
 * redirect to /login.
 */
export function useBootstrapSession() {
  const initialized = useAuthStore((s) => s.initialized);

  useEffect(() => {
    if (initialized) return;
    let cancelled = false;

    api
      .refresh()
      .then((res) => {
        if (!cancelled) {
          useAuthStore.getState().setSession(res.access_token, res.user);
        }
      })
      .catch(() => {
        // No valid refresh cookie (or mock mode with no prior login) — the
        // user lands on /login, which is the expected unauthenticated state.
      })
      .finally(() => {
        if (!cancelled) useAuthStore.getState().setInitialized();
      });

    return () => {
      cancelled = true;
    };
    // Intentionally run once per mount regardless of `initialized` changing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}

export function useLogin() {
  return useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      api.login(email, password),
    onSuccess: (res) => {
      useAuthStore.getState().setSession(res.access_token, res.user);
      useAuthStore.getState().setInitialized();
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return useMutation({
    mutationFn: () => api.logout(),
    onSettled: () => {
      // Logout is treated as always-successful client-side: even if the
      // network call fails, dropping the local token ends the session.
      useAuthStore.getState().clear();
      qc.clear();
      navigate("/login", { replace: true });
    },
  });
}
