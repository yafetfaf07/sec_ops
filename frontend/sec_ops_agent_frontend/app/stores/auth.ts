import { create } from "zustand";
import type { AuthUser } from "~/lib/types";

/**
 * Holds the in-memory session: the access token and the authenticated user.
 *
 * Deliberately NOT persisted to localStorage/sessionStorage: an access token
 * sitting in web storage is readable by any script on the page (XSS), while
 * an httpOnly cookie is not. The refresh token lives only in the httpOnly,
 * Secure cookie the backend sets on /auth/login — this store never sees it.
 * On a hard reload the access token is gone and `useMe` (queries.ts) calls
 * POST /auth/refresh once on mount to mint a fresh one from that cookie.
 */
interface AuthState {
  accessToken: string | null;
  user: AuthUser | null;
  /** True once the initial session bootstrap (refresh-on-load) has settled. */
  initialized: boolean;
  setSession: (accessToken: string, user: AuthUser) => void;
  setUser: (user: AuthUser) => void;
  setInitialized: () => void;
  clear: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
  accessToken: null,
  user: null,
  initialized: false,
  setSession: (accessToken, user) => set({ accessToken, user }),
  setUser: (user) => set({ user }),
  setInitialized: () => set({ initialized: true }),
  clear: () => set({ accessToken: null, user: null }),
}));

export function useIsAuthenticated() {
  return useAuthStore((s) => s.accessToken !== null && s.user !== null);
}

export function useAuthUser() {
  return useAuthStore((s) => s.user);
}

export function useCanTriage() {
  const role = useAuthStore((s) => s.user?.role);
  return role === "admin" || role === "analyst";
}

export function useIsAdmin() {
  return useAuthStore((s) => s.user?.role === "admin");
}
