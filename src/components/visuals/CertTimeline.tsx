import {
  FileCheck2,
  RefreshCw,
  CalendarClock,
  AlertTriangle,
} from "lucide-react";
import { Diagram, Flow, palette } from "./Diagram";
export function CertTimeline() {
  return (
    <Diagram
      title="Auto-renewal still needs monitoring"
      summary="A certificate is issued, renewal is attempted before expiry, and successful renewal replaces the certificate. A failed renewal can reach expiry and break trust. Monitor the actual expiry date; no universal duration is assumed."
      caption="Conceptual timeline, not to scale. Use the actual certificate dates and renewal configuration."
    >
      <Flow
        nodes={[
          {
            title: "Issued",
            lines: ["Correct hostname", "Trusted certificate chain"],
            icon: FileCheck2,
          },
          {
            title: "Renewal window",
            lines: [
              "Monitor renewal attempts",
              "Investigate failed challenges",
            ],
            icon: RefreshCw,
          },
          {
            title: "Expiry boundary",
            lines: ["Replacement must be valid", "before the old cert expires"],
            icon: CalendarClock,
            color: palette.amber,
          },
        ]}
      />
      <div className="mt-5 flex gap-3 rounded-xl border border-[#ff6b6b]/25 bg-[#ff6b6b]/[0.05] p-4">
        <AlertTriangle
          aria-hidden="true"
          size={20}
          className="shrink-0 text-[#ff6b6b]"
        />
        <p className="text-xs leading-6 text-[#98a2b3]">
          <span className="font-semibold text-[#ff9696]">
            Expired without replacement:
          </span>{" "}
          browsers may reject the connection. Automatic renewal is a mechanism,
          not evidence that renewal succeeded.
        </p>
      </div>
    </Diagram>
  );
}
