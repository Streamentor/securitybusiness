import { Globe2, Github } from "lucide-react";
import { Diagram, palette } from "./Diagram";
export function OutsideInsideDiagram() {
  return (
    <Diagram
      title="Two views of your app"
      summary="Website scans inspect public TLS, headers, cookies, files, source maps and CORS. Repository scans inspect committed secrets, migration RLS signals, Actions, public environment variables and dependencies. Paid AI review inspects selected routes; neither view proves security."
    >
      <div className="grid gap-3 sm:grid-cols-[1fr_auto_1fr]">
        <div className="rounded-xl border border-[#7b91ff]/25 bg-[#7b91ff]/[0.04] p-5">
          <Globe2 aria-hidden="true" color={palette.cobalt} size={25} />
          <p className="mt-4 font-semibold text-[#aab9ff]">Website scan sees</p>
          <ul className="mt-4 space-y-2 text-sm text-[#98a2b3]">
            {[
              "TLS and HTTPS",
              "Headers and cookies",
              "Exposed files and source maps",
              "CORS responses",
            ].map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
        <div className="flex items-center justify-center gap-3 py-3 text-[10px] uppercase tracking-widest text-[#98a2b3]">
          <span className="h-px w-6 bg-white/15 sm:hidden" />
          <span>your app</span>
          <span className="h-px w-6 bg-white/15 sm:hidden" />
        </div>
        <div className="rounded-xl border border-[#b9ff66]/25 bg-[#b9ff66]/[0.04] p-5">
          <Github aria-hidden="true" color={palette.lime} size={25} />
          <p className="mt-4 font-semibold text-[#b9ff66]">Repo scan sees</p>
          <ul className="mt-4 space-y-2 text-sm text-[#98a2b3]">
            {[
              "Committed secrets / public env vars",
              "RLS signals in migrations",
              "GitHub Actions and dependencies",
              "Selected routes: paid AI review",
            ].map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </div>
      </div>
      <svg className="mt-5 h-5 w-full" aria-hidden="true" viewBox="0 0 600 20">
        <path d="M0 10h260m80 0h260" stroke="#ffffff18" />
        <circle cx="300" cy="10" r="5" fill={palette.lime} />
      </svg>
    </Diagram>
  );
}
