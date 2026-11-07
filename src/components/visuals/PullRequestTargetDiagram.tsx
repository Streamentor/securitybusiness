import {
  GitFork,
  KeyRound,
  GitPullRequestArrow,
  ShieldCheck,
} from "lucide-react";
import { Diagram, Flow, palette } from "./Diagram";
export function PullRequestTargetDiagram() {
  return (
    <Diagram
      title="Untrusted PR code must not inherit trusted authority"
      summary="Dangerous pattern: a fork PR triggers pull_request_target, then a trusted workflow with secrets and a write token checks out and runs the PR head. Safer untrusted-code checks use pull_request with read-only permissions and no secrets. Actual token and secret availability depends on configuration."
      caption="The dangerous combination is trusted credentials plus executing untrusted PR code. This is a workflow illustration, not a scanner finding."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <div>
          <p className="mb-3 text-xs font-semibold text-[#ff9696]">
            Risky combination
          </p>
          <Flow
            stacked
            nodes={[
              {
                title: "Fork PR",
                lines: ["Untrusted contributor code"],
                icon: GitFork,
                color: palette.amber,
              },
              {
                title: "pull_request_target",
                lines: [
                  "Trusted workflow context",
                  "Secrets / write token if granted",
                ],
                icon: KeyRound,
                color: palette.red,
              },
              {
                title: "Checkout PR head",
                lines: [
                  "Untrusted code runs with",
                  "the workflow’s credentials",
                ],
                icon: GitPullRequestArrow,
                color: palette.red,
              },
            ]}
          />
        </div>
        <div>
          <p className="mb-3 text-xs font-semibold text-[#b9ff66]">
            Safer untrusted-code checks
          </p>
          <Flow
            stacked
            nodes={[
              {
                title: "Fork PR",
                lines: ["Treat changes as untrusted"],
                icon: GitFork,
              },
              {
                title: "pull_request",
                lines: ["contents: read", "No repository secrets"],
                icon: ShieldCheck,
              },
              {
                title: "Run isolated checks",
                lines: ["Keep trusted release jobs", "separate from PR code"],
                icon: GitPullRequestArrow,
              },
            ]}
          />
        </div>
      </div>
    </Diagram>
  );
}
