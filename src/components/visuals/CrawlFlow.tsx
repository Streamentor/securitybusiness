import { Bot, FileText, Map, Globe2 } from "lucide-react";
import { Diagram, Flow } from "./Diagram";
export function CrawlFlow() {
  return (
    <Diagram
      title="Discovery, crawling and indexing are different decisions"
      summary="Googlebot discovers URLs through links and sitemaps, checks robots.txt before fetching pages, then can read canonical and noindex signals on allowed pages. A sitemap does not override robots.txt; blocking crawling can prevent a noindex directive from being seen."
      caption="A sitemap helps discovery; it does not grant crawl permission or guarantee indexing."
    >
      <Flow
        nodes={[
          {
            title: "sitemap.xml / links",
            lines: ["Discover URLs", "Prefer canonical, indexable URLs"],
            icon: Map,
          },
          {
            title: "Googlebot",
            lines: ["Selects a discovered URL", "for possible crawling"],
            icon: Bot,
          },
          {
            title: "robots.txt",
            lines: [
              "Allow: may fetch the page",
              "Disallow: cannot read its tags",
            ],
            icon: FileText,
          },
          {
            title: "Page response",
            lines: ["Canonical: preferred version", "noindex: exclude if seen"],
            icon: Globe2,
          },
        ]}
      />
    </Diagram>
  );
}
