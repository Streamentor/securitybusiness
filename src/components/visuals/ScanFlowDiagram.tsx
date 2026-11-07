import { Globe2, Map, ScanLine, ListChecks, Bot, RotateCw } from "lucide-react";
import { Diagram, Flow } from "./Diagram";
export function ScanFlowDiagram({
  maxPages,
  checkCount,
}: {
  maxPages: number;
  checkCount: string;
}) {
  const nodes = [
    { title: "Your URL", lines: ["A site you own or may test"], icon: Globe2 },
    {
      title: `Crawl up to ${maxPages} pages`,
      lines: ["Discover reachable pages"],
      icon: Map,
    },
    {
      title: `${checkCount} checks`,
      lines: ["Read-only requests", "No login or form submission"],
      icon: ScanLine,
    },
    {
      title: "Prioritized report",
      lines: ["Findings with affected URLs"],
      icon: ListChecks,
    },
    {
      title: "Fix prompt",
      lines: ["Cursor / Claude / Codex", "Confirm the issue first"],
      icon: Bot,
    },
    { title: "Rescan", lines: ["Verify the deployed change"], icon: RotateCw },
  ];
  return (
    <Diagram
      title="From URL to verification"
      summary={`Submit an authorized URL, crawl up to ${maxPages} pages, run ${checkCount} checks, review findings and affected URLs, confirm and fix with your coding tool, then rescan.`}
      caption="What happens when you press Scan."
    >
      <Flow nodes={nodes} />
    </Diagram>
  );
}
