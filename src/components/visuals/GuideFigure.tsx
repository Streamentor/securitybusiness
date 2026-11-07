import type { GuideSection } from "@/lib/guides";
import { HeaderAnatomy } from "./HeaderAnatomy";
import { CertTimeline } from "./CertTimeline";
import { LeakTimeline } from "./LeakTimeline";
import { PullRequestTargetDiagram } from "./PullRequestTargetDiagram";
import { CrawlFlow } from "./CrawlFlow";
import { RlsRequestFlow } from "./RlsRequestFlow";
import { BoundaryMap } from "./BoundaryMap";
export function GuideFigure({ kind }: { kind: GuideSection["figure"] }) {
  switch (kind) {
    case "header-anatomy":
      return <HeaderAnatomy />;
    case "cert-timeline":
      return <CertTimeline />;
    case "leak-timeline":
      return <LeakTimeline />;
    case "pr-target":
      return <PullRequestTargetDiagram />;
    case "crawl-flow":
      return <CrawlFlow />;
    case "rls-flow":
      return <RlsRequestFlow />;
    case "boundary-map":
      return <BoundaryMap />;
    default:
      return null;
  }
}
