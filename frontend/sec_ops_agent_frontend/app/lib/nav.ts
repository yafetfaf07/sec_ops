import {
  ClipboardList,
  LayoutDashboard,
  ScrollText,
  Settings,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  adminOnly?: boolean;
  end?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/logs", label: "Logs", icon: ScrollText },
  { to: "/audit", label: "Audit Log", icon: ClipboardList },
  { to: "/settings", label: "Settings", icon: Settings, adminOnly: true },
];
