import { Diagram } from "./Diagram";
const headers = [
  [
    "Content-Security-Policy:",
    "default-src 'self'; frame-ancestors 'none'",
    "Limits resource sources; frame-ancestors controls framing.",
  ],
  [
    "Strict-Transport-Security:",
    "max-age=<reviewed duration>",
    "Return over HTTPS after a secure visit; stage the rollout.",
  ],
  [
    "X-Content-Type-Options:",
    "nosniff",
    "Do not guess a different content type.",
  ],
  [
    "Referrer-Policy:",
    "strict-origin-when-cross-origin",
    "Limit cross-origin referrer detail.",
  ],
];
export function HeaderAnatomy() {
  return (
    <Diagram
      title="Anatomy of the browser-facing response"
      summary="Illustrative HTTP response: CSP limits resource sources and contains frame-ancestors to control framing; HSTS requires HTTPS on repeat visits; nosniff prevents MIME guessing; Referrer-Policy limits referrer detail. Adapt policies to your app and start CSP in report-only mode."
      caption="Illustrative response, not a copy-paste production policy. Inventory required resources and test report-only CSP before enforcement."
    >
      <div className="rounded-xl border border-white/10 bg-[#07090d] p-4 sm:p-6">
        <p className="mb-5 font-mono text-xs text-[#b9ff66]">HTTP/2 200 OK</p>
        <div className="divide-y divide-white/[0.07]">
          {headers.map(([name, value, note]) => (
            <div
              key={name}
              className="grid gap-3 py-4 lg:grid-cols-[1.2fr_1fr]"
            >
              <div className="min-w-0 break-words font-mono text-[11px] leading-6 sm:text-xs">
                <span className="text-[#aab9ff]">{name}</span>
                <br />
                <span className="text-[#d7e0eb]">{value}</span>
              </div>
              <p className="text-xs leading-6 text-[#98a2b3]">{note}</p>
            </div>
          ))}
        </div>
      </div>
    </Diagram>
  );
}
