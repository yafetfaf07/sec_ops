import axios from "axios";
import { useAuthStore } from "~/stores/auth";
import type { AuthUser } from "~/lib/types";

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL as
  | string
  | undefined;

/** When no backend base URL is configured we serve everything from the mock layer. */
export const USE_MOCK = !API_BASE_URL;

export const http = axios.create({
  baseURL: API_BASE_URL ?? "/",
  headers: { "Content-Type": "application/json" },
  timeout: 15000,
  // Required so the browser sends/receives the httpOnly refresh_token cookie
  // the Go backend sets on /auth/login and reads on /auth/refresh.
  withCredentials: true,
});

// Attach the current access token to every outgoing request.
http.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

interface LoginResponseLike {
  access_token: string;
  user: AuthUser;
}

// Serialises concurrent refresh attempts: if five requests 401 at once, only
// one refresh call is made and the rest wait on it.
let refreshPromise: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  if (!refreshPromise) {
    refreshPromise = http
      .post<LoginResponseLike>("/api/v1/auth/refresh")
      .then((res) => {
        useAuthStore
          .getState()
          .setSession(res.data.access_token, res.data.user);
        return res.data.access_token;
      })
      .catch(() => {
        useAuthStore.getState().clear();
        return null;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

// On a 401 (expired/invalid access token), try exactly one silent refresh via
// the refresh cookie and replay the original request. Never retries a second
// time, and never retries the refresh/login endpoints themselves.
http.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;
    const url = original?.url ?? "";
    const isAuthEndpoint =
      url.includes("/auth/login") ||
      url.includes("/auth/refresh") ||
      url.includes("/auth/logout");

    if (status !== 401 || isAuthEndpoint || original?._retried) {
      return Promise.reject(error);
    }
    original._retried = true;

    const newToken = await refreshAccessToken();
    if (!newToken) {
      return Promise.reject(error);
    }
    original.headers = original.headers ?? {};
    original.headers.Authorization = `Bearer ${newToken}`;
    return http(original);
  },
);
