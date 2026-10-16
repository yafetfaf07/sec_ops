import { useEffect, useState } from "react";
import type { Route } from "./+types/settings";
import { toast } from "sonner";
import { CalendarClockIcon, KeyRoundIcon, SendIcon } from "lucide-react";
import { useSettings, useUpdateSettings } from "~/lib/queries";
import type { SchedulerSettings } from "~/lib/types";
import { PageHeader } from "~/components/page-header";
import { RequireAdmin } from "~/components/require-role";
import { Card, CardContent, CardHeader, CardTitle } from "~/components/ui/card";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { Label } from "~/components/ui/label";
import { Switch } from "~/components/ui/switch";
import { Skeleton } from "~/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "~/components/ui/select";

export function meta({}: Route.MetaArgs) {
  return [{ title: "Settings · SecOps Agent" }];
}

export default function Settings() {
  return (
    <RequireAdmin>
      <SettingsInner />
    </RequireAdmin>
  );
}

function SettingsInner() {
  const { data, isLoading } = useSettings();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Configure scheduled scans, threat intelligence and alert dispatch. Admin only."
      />
      {isLoading || !data ? (
        <div className="grid gap-4">
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-40 w-full" />
        </div>
      ) : (
        <SettingsForm initial={data} />
      )}
    </div>
  );
}

function SettingsForm({ initial }: { initial: SchedulerSettings }) {
  const update = useUpdateSettings();
  const [form, setForm] = useState<SchedulerSettings>(initial);

  useEffect(() => setForm(initial), [initial]);

  const set = <K extends keyof SchedulerSettings>(
    key: K,
    value: SchedulerSettings[K],
  ) => setForm((f) => ({ ...f, [key]: value }));

  const dirty = JSON.stringify(form) !== JSON.stringify(initial);

  const save = () => {
    update.mutate(form, {
      onSuccess: () => toast.success("Settings saved"),
      onError: () => toast.error("Could not save settings."),
    });
  };

  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CalendarClockIcon className="size-4 text-muted-foreground" aria-hidden />
            Scheduled scanning
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-center justify-between gap-4">
            <div className="space-y-0.5">
              <Label htmlFor="sched-enabled">Enable daily scan</Label>
              <p className="text-xs text-muted-foreground">
                GCP Cloud Scheduler triggers{" "}
                <code className="rounded bg-muted px-1 py-0.5 text-[0.7rem]">
                  /api/v1/scan/daily
                </code>{" "}
                every 24 hours.
              </p>
            </div>
            <Switch
              id="sched-enabled"
              checked={form.enabled}
              onCheckedChange={(v) => set("enabled", v)}
            />
          </div>

          <div className="grid gap-1.5 sm:max-w-xs">
            <Label htmlFor="sched-hour">Scan hour (UTC)</Label>
            <Select
              value={String(form.cron_hour_utc)}
              onValueChange={(v) => set("cron_hour_utc", Number(v))}
              disabled={!form.enabled}
            >
              <SelectTrigger id="sched-hour" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Array.from({ length: 24 }).map((_, h) => (
                  <SelectItem key={h} value={String(h)}>
                    {String(h).padStart(2, "0")}:00
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRoundIcon className="size-4 text-muted-foreground" aria-hidden />
            Threat intelligence & model
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-1.5 sm:max-w-xs">
            <Label htmlFor="gemini-model">Gemini model</Label>
            <Select
              value={form.gemini_model}
              onValueChange={(v) => set("gemini_model", v as string)}
            >
              <SelectTrigger id="gemini-model" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="gemini-1.5-flash">gemini-1.5-flash</SelectItem>
                <SelectItem value="gemini-1.5-pro">gemini-1.5-pro</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Flash keeps usage within the free tier.
            </p>
          </div>

          <div className="grid gap-1.5 sm:max-w-xs">
            <Label htmlFor="abuseipdb-key">AbuseIPDB API key</Label>
            <Input
              id="abuseipdb-key"
              type="password"
              placeholder="••••••••••••"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Stored server-side and never sent to the browser.
            </p>
          </div>

          <div className="flex items-center justify-between gap-4">
            <div className="space-y-0.5">
              <Label htmlFor="abuse-enabled">AbuseIPDB enrichment</Label>
              <p className="text-xs text-muted-foreground">
                Cross-reference high-risk IPs; responses cached for 24 hours.
              </p>
            </div>
            <Switch
              id="abuse-enabled"
              checked={form.abuseipdb_enabled}
              onCheckedChange={(v) => set("abuseipdb_enabled", v)}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <SendIcon className="size-4 text-muted-foreground" aria-hidden />
            Alert dispatch
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <WebhookRow
            id="slack"
            label="Slack webhook"
            enabled={form.slack_webhook_set}
            onToggle={(v) => set("slack_webhook_set", v)}
          />
          <WebhookRow
            id="discord"
            label="Discord webhook"
            enabled={form.discord_webhook_set}
            onToggle={(v) => set("discord_webhook_set", v)}
          />
        </CardContent>
      </Card>

      <div className="flex items-center justify-end gap-2">
        <Button
          variant="ghost"
          onClick={() => setForm(initial)}
          disabled={!dirty || update.isPending}
        >
          Reset
        </Button>
        <Button onClick={save} disabled={!dirty || update.isPending}>
          {update.isPending ? "Saving…" : "Save changes"}
        </Button>
      </div>
    </div>
  );
}

function WebhookRow({
  id,
  label,
  enabled,
  onToggle,
}: {
  id: string;
  label: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
}) {
  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-4">
        <Label htmlFor={`${id}-enabled`}>{label}</Label>
        <Switch
          id={`${id}-enabled`}
          checked={enabled}
          onCheckedChange={onToggle}
        />
      </div>
      <Input
        id={`${id}-url`}
        type="password"
        placeholder="https://hooks…"
        autoComplete="off"
        disabled={!enabled}
      />
    </div>
  );
}
