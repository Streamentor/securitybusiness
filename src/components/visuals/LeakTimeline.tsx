import {
  GitCommitHorizontal,
  GitBranch,
  History,
  KeyRound,
  Eraser,
  ShieldCheck,
} from "lucide-react";
import { Diagram, Flow, palette } from "./Diagram";
export function LeakTimeline() {
  return (
    <Diagram
      title="A deleted file can leave a live credential behind"
      summary="A committed key pushed to a public repository remains in history. Rotate or revoke the key first, purge history with a coordinated cleanup, and enable push protection to reduce future leaks. Deleting the current file is not enough."
      caption="Deleting the file is not enough. Revoke or rotate first; coordinate any history rewrite with collaborators."
    >
      <Flow
        nodes={[
          {
            title: "Commit",
            lines: ["Credential enters a snapshot"],
            icon: GitCommitHorizontal,
          },
          {
            title: "Push",
            lines: ["Snapshot reaches the remote"],
            icon: GitBranch,
          },
          {
            title: "Public history",
            lines: ["Copies may already exist"],
            icon: History,
            color: palette.red,
          },
          {
            title: "Rotate key",
            lines: ["Revoke the exposed value"],
            icon: KeyRound,
          },
          {
            title: "Purge history",
            lines: ["Coordinate cleanup", "A rewrite cannot erase copies"],
            icon: Eraser,
          },
          {
            title: "Push protection",
            lines: ["Reduce future secret pushes"],
            icon: ShieldCheck,
          },
        ]}
      />
    </Diagram>
  );
}
