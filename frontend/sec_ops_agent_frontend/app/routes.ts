import {
  type RouteConfig,
  index,
  layout,
  route,
} from "@react-router/dev/routes";

export default [
  route("login", "routes/login.tsx"),
  layout("routes/layout.tsx", [
    index("routes/dashboard.tsx"),
    route("incidents", "routes/incidents.tsx"),
    route("logs", "routes/logs.tsx"),
    route("audit", "routes/audit.tsx"),
    route("settings", "routes/settings.tsx"),
  ]),
] satisfies RouteConfig;
