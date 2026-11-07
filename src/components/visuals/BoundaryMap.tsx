import { Monitor, Globe2, Server, Database } from "lucide-react";
import { Diagram, Flow, Block, palette } from "./Diagram";
export function BoundaryMap() {
  return (
    <Diagram
      title="Where authority changes hands"
      summary="Five boundaries: 1 Secrets, 2 Authorization, 3 Data access, 4 CI and releases, 5 Public app. Browser requests reach the public app edge, server routes, and database; CI publishes the release. Verify each boundary independently."
    >
      <Flow
        nodes={[
          {
            title: "Browser",
            badge: "1 · SECRETS",
            lines: ["Public bundle ≠ secret store"],
            icon: Monitor,
            color: palette.cobalt,
          },
          {
            title: "Public app edge",
            badge: "5 · PUBLIC APP",
            lines: ["TLS, headers and exposure"],
            icon: Globe2,
            color: palette.cobalt,
          },
          {
            title: "Server routes",
            badge: "2 · AUTHORIZATION",
            lines: ["Check user, role and owner"],
            icon: Server,
          },
          {
            title: "Database",
            badge: "3 · DATA ACCESS",
            lines: ["Policies, tenants and storage"],
            icon: Database,
          },
        ]}
      />
      <div className="mt-5 sm:ml-auto sm:max-w-xs">
        <Block title="4 · GitHub / CI → app release" color={palette.amber}>
          Review workflow permissions, untrusted PR code and deployment secrets.
        </Block>
      </div>
    </Diagram>
  );
}
