import {
  Github,
  KeyRound,
  GitCommitHorizontal,
  Files,
  FileCheck2,
} from "lucide-react";
import { Diagram, Flow } from "./Diagram";
export function PrivateAccessDiagram() {
  return (
    <Diagram
      title="Read-only repository access"
      summary="Your GitHub App grants contents: read and metadata: read for selected repositories. The scanner resolves one pinned commit and reads up to 60 highest-risk files in memory to produce a report. It never clones, installs or runs code."
      caption="Never clones, installs or runs your code. Selected source files are read in memory; paid AI review has its own disclosed processing limits."
    >
      <Flow
        nodes={[
          {
            title: "Your GitHub",
            lines: ["Repositories you choose"],
            icon: Github,
          },
          {
            title: "Read-only GitHub App",
            lines: ["contents: read", "metadata: read"],
            icon: KeyRound,
          },
          {
            title: "One pinned commit",
            lines: ["One snapshot for every file"],
            icon: GitCommitHorizontal,
          },
          {
            title: "Up to 60 files",
            lines: ["Highest-risk files first", "Read in memory"],
            icon: Files,
          },
          {
            title: "Your private report",
            lines: ["File and line evidence", "Review before changing code"],
            icon: FileCheck2,
          },
        ]}
      />
    </Diagram>
  );
}
