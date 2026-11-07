import { Diagram, Block, Connector, palette } from "./Diagram";
export function RlsRequestFlow() {
  return (
    <Diagram
      title="One table. Three different authority levels."
      summary="Illustrative owner-only SELECT policy with table grants configured: an anonymous request reads no rows, signed-in user A reads only A rows, and a server-only secret/service-role request bypasses RLS. Actual results depend on grants, policies and the authorization context."
      caption="Example policy: auth.uid() = owner_id. Test anonymous, owner and different-user access with synthetic records."
    >
      <div className="grid gap-5 sm:grid-cols-3">
        {[
          {
            title: "Anon / publishable key",
            color: palette.cobalt,
            authority: "No signed-in user",
            rows: [false, false],
            result: "No rows under this policy",
          },
          {
            title: "Signed-in user A",
            color: palette.lime,
            authority: "User JWT + publishable key",
            rows: [true, false],
            result: "Only permitted A rows",
          },
          {
            title: "Secret / service role",
            color: palette.amber,
            authority: "Server only · bypasses RLS",
            rows: [true, true],
            result: "Privileged access to all rows",
          },
        ].map((lane) => (
          <div key={lane.title}>
            <Block title={lane.title} color={lane.color}>
              {lane.authority}
            </Block>
            <Connector color={lane.color} />
            <div className="rounded-xl border border-white/10 bg-[#07090d] p-4">
              <p className="mb-3 text-[10px] uppercase tracking-widest text-[#98a2b3]">
                Example table
              </p>
              {["A’s row", "B’s row"].map((row, i) => (
                <div
                  key={row}
                  className="mt-2 flex justify-between rounded-md border px-3 py-2 text-xs"
                  style={{
                    color: lane.rows[i] ? lane.color : palette.muted,
                    borderColor: lane.rows[i] ? `${lane.color}50` : "#ffffff14",
                  }}
                >
                  {row}
                  <span>{lane.rows[i] ? "Visible" : "Blocked"}</span>
                </div>
              ))}
              <p className="mt-3 text-xs leading-5 text-[#98a2b3]">
                {lane.result}
              </p>
            </div>
          </div>
        ))}
      </div>
    </Diagram>
  );
}
