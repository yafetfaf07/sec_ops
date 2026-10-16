import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { CornerDownLeftIcon, Loader2Icon, SparklesIcon } from "lucide-react";
import { api } from "~/lib/api/endpoints";
import { useCommandStore, type ChatMessage } from "~/stores/command";
import { Button } from "~/components/ui/button";
import { Input } from "~/components/ui/input";
import { cn } from "cn";

const SUGGESTIONS = [
  "Show failed logins from Germany in the last 24 hours",
  "Any critical incidents today?",
  "Privilege escalation in the last 7 days",
];

function newId() {
  return `msg_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
}

export function CommandInterface() {
  const [value, setValue] = useState("");
  const messages = useCommandStore((s) => s.messages);
  const pending = useCommandStore((s) => s.pending);
  const addMessage = useCommandStore((s) => s.addMessage);
  const setPending = useCommandStore((s) => s.setPending);

  const scrollRef = useRef<HTMLDivElement>(null);

  const query = useMutation({
    mutationFn: (q: string) => api.runNaturalLanguageQuery(q),
  });

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages.length, pending]);

  const submit = (raw?: string) => {
    const text = (raw ?? value).trim();
    if (!text || pending) return;
    setValue("");
    addMessage({ id: newId(), role: "user", text, created_at: Date.now() });
    setPending(true);
    query.mutate(text, {
      onSuccess: (result) => {
        const matched =
          result.matched_incident_ids.length +
          result.matched_log_ids.length;
        addMessage({
          id: newId(),
          role: "assistant",
          text:
            matched > 0
              ? `${result.interpretation}`
              : `${result.interpretation} Try widening the time window or removing a filter.`,
          result,
          created_at: Date.now(),
        });
      },
      onError: () => {
        addMessage({
          id: newId(),
          role: "assistant",
          text: "I couldn't process that request. Please try rephrasing.",
          created_at: Date.now(),
        });
      },
      onSettled: () => setPending(false),
    });
  };

  return (
    <div className="flex flex-col">
      <div
        ref={scrollRef}
        className="max-h-80 min-h-40 overflow-y-auto px-(--card-spacing)"
      >
        {messages.length === 0 ? (
          <div className="flex h-40 flex-col items-center justify-center gap-3 text-center">
            <div className="flex size-8 items-center justify-center rounded-lg bg-muted text-muted-foreground">
              <SparklesIcon className="size-4" aria-hidden />
            </div>
            <p className="text-sm text-muted-foreground">
              Ask the SecOps agent about your security posture.
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => submit(s)}
                  className="rounded-4xl border border-border px-3 py-1 text-xs text-muted-foreground transition-colors duration-150 hover:bg-muted hover:text-foreground focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <ul className="flex flex-col gap-3 py-1">
            {messages.map((m) => (
              <MessageRow key={m.id} message={m} />
            ))}
            {pending ? (
              <li className="flex items-center gap-2 text-sm text-muted-foreground animate-in fade-in-0 duration-200">
                <Loader2Icon className="size-4 animate-spin" aria-hidden />
                Analyzing logs…
              </li>
            ) : null}
          </ul>
        )}
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="flex items-center gap-2 px-(--card-spacing) pt-1"
      >
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="e.g. Show me all failed logins from Germany in the last 24 hours"
          aria-label="Natural language query"
          disabled={pending}
        />
        <Button type="submit" disabled={pending || value.trim().length === 0}>
          {pending ? (
            <Loader2Icon className="animate-spin" aria-hidden />
          ) : (
            <CornerDownLeftIcon aria-hidden />
          )}
          <span className="sr-only">Send query</span>
        </Button>
      </form>
    </div>
  );
}

function MessageRow({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";
  return (
    <li
      className={cn(
        "flex animate-in fade-in-0 slide-in-from-bottom-1 duration-200 ease-out",
        isUser ? "justify-end" : "justify-start",
      )}
    >
      <div
        className={cn(
          "max-w-[85%] rounded-lg px-3 py-2 text-sm",
          isUser
            ? "bg-primary text-primary-foreground"
            : "bg-muted text-foreground",
        )}
      >
        {message.text}
        {message.result &&
        Object.keys(message.result.filters_applied).length > 0 ? (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {Object.entries(message.result.filters_applied).map(
              ([k, v]) => (
                <span
                  key={k}
                  className="rounded-4xl bg-background/60 px-2 py-0.5 text-xs text-muted-foreground tabular-nums"
                >
                  {k}: {v}
                </span>
              ),
            )}
          </div>
        ) : null}
      </div>
    </li>
  );
}
