import { Diagram, Block, Connector, palette } from "./Diagram";
export function LovableStackDiagram() {
  return (
    <Diagram
      title="The browser key is public. The boundary is the policy."
      summary="A React browser bundle includes a publishable key. Requests reach the Supabase Data API, where grants and RLS policies control table access. With SELECT granted, disabled RLS or an unconditional true policy can expose rows. Server functions must verify caller identity independently of a body user ID."
      caption="Illustrative permission model, not a scan result. Exposure also depends on table grants, roles and policies; verify the actual request path."
    >
      <div className="grid gap-6 lg:grid-cols-[1fr_.8fr]">
        <div>
          <Block title="Browser · React bundle" color={palette.cobalt}>
            Publishable key is expected to be visible.
          </Block>
          <Connector label="User-controlled requests" color={palette.cobalt} />
          <Block title="Supabase Data API">
            Database grants + RLS policies
          </Block>
          <Connector />
          <div className="grid gap-3 sm:grid-cols-3">
            <Block title="Owner-only RLS">
              User A sees only A’s permitted rows.
            </Block>
            <Block title="No RLS" color={palette.red}>
              With SELECT granted: anyone with the publishable key may read
              rows.
            </Block>
            <Block title="using (true)" color={palette.amber}>
              With SELECT granted: all rows for the targeted role.
            </Block>
          </div>
        </div>
        <div className="flex flex-col justify-between gap-5">
          <Block title="Edge function" color={palette.amber}>
            Trusts user ID from body?
            <br />
            Verify caller identity and ownership on the server.
          </Block>
          <div className="rounded-xl border border-dashed border-white/15 p-4">
            <p className="text-sm text-white">Lovable ↔ GitHub sync</p>
            <Connector label="Repository view" />
            <p className="text-xs leading-6 text-[#98a2b3]">
              Repo scan reads migrations for visible RLS signals. It does not
              prove the deployed policies.
            </p>
          </div>
        </div>
      </div>
    </Diagram>
  );
}
