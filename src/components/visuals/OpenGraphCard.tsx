import { ImageResponse } from "next/og";

export function openGraphCard(title: string, subtitle: string) {
  const words = title.split(" ");
  return new ImageResponse(
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: "#07090d",
        color: "white",
        padding: "52px 64px",
        fontFamily: "sans-serif",
        position: "relative",
      }}
    >
      <div
        style={{
          display: "flex",
          position: "absolute",
          top: 0,
          left: 0,
          width: 1200,
          height: 630,
          opacity: 0.35,
        }}
      >
        {Array.from({ length: 16 }, (_, i) => (
          <div
            key={`v${i}`}
            style={{
              display: "flex",
              position: "absolute",
              left: i * 80,
              top: 0,
              width: 1,
              height: 630,
              background: "#253040",
            }}
          />
        ))}
        {Array.from({ length: 8 }, (_, i) => (
          <div
            key={`h${i}`}
            style={{
              display: "flex",
              position: "absolute",
              top: i * 80,
              left: 0,
              height: 1,
              width: 1200,
              background: "#253040",
            }}
          />
        ))}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 14,
          fontSize: 27,
          fontWeight: 700,
        }}
      >
        <svg width="42" height="42" viewBox="0 0 42 42">
          <rect width="42" height="42" rx="12" fill="#b9ff66" />
          <circle
            cx="21"
            cy="21"
            r="12"
            fill="none"
            stroke="#07090d"
            strokeWidth="2"
          />
          <circle
            cx="21"
            cy="21"
            r="6"
            fill="none"
            stroke="#07090d"
            strokeWidth="2"
          />
          <path d="M21 21 32 10" stroke="#07090d" strokeWidth="2" />
        </svg>
        <span>
          ScanMy<span style={{ color: "#b9ff66" }}>SaaS</span>
        </span>
      </div>
      <div
        style={{
          display: "flex",
          flex: 1,
          justifyContent: "center",
          flexDirection: "column",
          paddingTop: 18,
        }}
      >
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            width: "100%",
            gap: 15,
            fontSize: 64,
            fontWeight: 700,
            lineHeight: 1.08,
            letterSpacing: "-2.5px",
          }}
        >
          {words.map((word, index) => (
            <span
              key={`${index}-${word}`}
              style={{
                display: "flex",
                flexShrink: 0,
                color: index === words.length - 1 ? "#b9ff66" : "white",
              }}
            >
              {word}
            </span>
          ))}
        </div>
        <p
          style={{
            display: "flex",
            color: "#98a2b3",
            fontSize: 23,
            lineHeight: 1.4,
            margin: "24px 0 0",
            maxWidth: 1020,
          }}
        >
          {subtitle}
        </p>
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginTop: 20,
        }}
      >
        {[
          ["Critical", "#ff6b6b"],
          ["High", "#ffbf69"],
          ["Medium", "#f5d68b"],
          ["Low", "#98a2b3"],
        ].map(([label, color]) => (
          <div
            key={label}
            style={{
              display: "flex",
              border: `1px solid ${color}55`,
              borderRadius: 8,
              padding: "8px 16px",
              fontSize: 16,
              color,
              background: "#111720",
            }}
          >
            {label}
          </div>
        ))}
        <span style={{ marginLeft: "auto", color: "#98a2b3", fontSize: 18 }}>
          scanmysaas.com
        </span>
      </div>
    </div>,
    { width: 1200, height: 630 },
  );
}
