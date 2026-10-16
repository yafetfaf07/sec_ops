import { useState } from "react";
import { toast } from "sonner";
import { CheckCheckIcon, CircleCheckBigIcon } from "lucide-react";
import { useAcknowledgeIncident } from "~/lib/queries";
import { useCanTriage } from "~/stores/auth";
import type { Incident } from "~/lib/types";
import { Button } from "~/components/ui/button";
import { ResolveDialog } from "~/components/resolve-dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "~/components/ui/tooltip";

export function IncidentActions({
  incident,
  size = "sm",
  className,
}: {
  incident: Incident;
  size?: "sm" | "default";
  className?: string;
}) {
  const [resolveOpen, setResolveOpen] = useState(false);
  const acknowledge = useAcknowledgeIncident();
  const canTriage = useCanTriage();
  const isResolved = incident.status === "Resolved";

  const onAcknowledge = () => {
    acknowledge.mutate(
      { id: incident.id },
      {
        onSuccess: () => toast.success(`${incident.id} acknowledged`),
        onError: () => toast.error("Could not acknowledge incident."),
      },
    );
  };

  const buttons = (
    <div className={className}>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="outline"
          size={size}
          onClick={onAcknowledge}
          disabled={
            !canTriage || isResolved || acknowledge.isPending
          }
        >
          <CheckCheckIcon aria-hidden />
          Acknowledge
        </Button>
        <Button
          size={size}
          onClick={() => setResolveOpen(true)}
          disabled={!canTriage || isResolved}
        >
          <CircleCheckBigIcon aria-hidden />
          Resolve
        </Button>
      </div>
    </div>
  );

  if (canTriage) {
    return (
      <>
        {buttons}
        <ResolveDialog
          incident={incident}
          open={resolveOpen}
          onOpenChange={setResolveOpen}
        />
      </>
    );
  }

  return (
    <Tooltip>
      <TooltipTrigger render={<div className={className} />}>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size={size} disabled>
            <CheckCheckIcon aria-hidden />
            Acknowledge
          </Button>
          <Button size={size} disabled>
            <CircleCheckBigIcon aria-hidden />
            Resolve
          </Button>
        </div>
      </TooltipTrigger>
      <TooltipContent>
        The Read-Only Viewer role cannot change incident state.
      </TooltipContent>
    </Tooltip>
  );
}
