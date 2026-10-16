import { useState } from "react";
import { toast } from "sonner";
import { useResolveIncident } from "~/lib/queries";
import type { Incident } from "~/lib/types";
import { Button } from "~/components/ui/button";
import { Textarea } from "~/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "~/components/ui/dialog";

export function ResolveDialog({
  incident,
  open,
  onOpenChange,
}: {
  incident: Incident;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [comment, setComment] = useState("");
  const resolve = useResolveIncident();

  const submit = () => {
    if (comment.trim().length < 3) {
      toast.error("Add a short resolution note first.");
      return;
    }
    resolve.mutate(
      { id: incident.id, comment: comment.trim() },
      {
        onSuccess: () => {
          toast.success(`${incident.id} resolved`, {
            description: "The AI agent will not re-alert on this incident.",
          });
          onOpenChange(false);
          setComment("");
        },
        onError: () => toast.error("Could not resolve incident. Try again."),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Resolve {incident.id}</DialogTitle>
          <DialogDescription>
            Document the remediation. Resolved incidents stop generating alerts.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-2">
          <label
            htmlFor="resolution-comment"
            className="text-sm font-medium text-foreground"
          >
            Resolution note
          </label>
          <Textarea
            id="resolution-comment"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="e.g. Blocked IP at firewall level and forced password reset."
            rows={4}
            autoFocus
          />
        </div>
        <DialogFooter>
          <Button
            variant="ghost"
            onClick={() => onOpenChange(false)}
            disabled={resolve.isPending}
          >
            Cancel
          </Button>
          <Button onClick={submit} disabled={resolve.isPending}>
            {resolve.isPending ? "Resolving…" : "Mark resolved"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
