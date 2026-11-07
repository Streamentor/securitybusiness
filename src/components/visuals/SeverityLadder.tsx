import { Diagram, palette } from "./Diagram";
export function SeverityLadder() {
  return (
    <Diagram
      title="Priority is a starting point for verification"
      summary="Critical: verify potentially severe exposure first. High: review substantial access or data risks next. Medium: assess context and hardening gaps. Low: address lower-impact weaknesses. Severity is not proof of exploitability."
    >
      <ol className="grid gap-3 sm:grid-cols-2">
        {[
          {
            name: "Critical",
            color: palette.red,
            copy: "Verify potentially severe exposure first.",
          },
          {
            name: "High",
            color: "#ffae76",
            copy: "Review substantial access or data risks next.",
          },
          {
            name: "Medium",
            color: palette.amber,
            copy: "Assess context and missing protections.",
          },
          {
            name: "Low",
            color: palette.muted,
            copy: "Address lower-impact weaknesses.",
          },
        ].map((s, i) => (
          <li
            key={s.name}
            className="flex gap-4 rounded-xl border border-white/10 bg-[#111720] p-4"
          >
            <svg
              width="10"
              height="48"
              viewBox="0 0 10 48"
              aria-hidden="true"
              className="shrink-0"
            >
              <rect
                y={i * 8}
                width="8"
                height={48 - i * 8}
                rx="3"
                fill={s.color}
              />
            </svg>
            <div>
              <p className="text-sm font-semibold" style={{ color: s.color }}>
                {s.name}
              </p>
              <p className="mt-1 text-xs leading-6 text-[#98a2b3]">{s.copy}</p>
            </div>
          </li>
        ))}
      </ol>
    </Diagram>
  );
}
