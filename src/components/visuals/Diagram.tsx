import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Figure } from "./Figure";
export const palette = {
  ink: "#07090d",
  panel: "#111720",
  text: "#e6ebf2",
  muted: "#98a2b3",
  lime: "#b9ff66",
  cobalt: "#7b91ff",
  amber: "#ffbf69",
  red: "#ff6b6b",
};
export type DiagramNode = {
  title: string;
  lines: string[];
  icon?: LucideIcon;
  color?: string;
  badge?: string;
};
export function Diagram({
  title,
  summary,
  children,
  caption,
}: {
  title: string;
  summary: string;
  children: ReactNode;
  caption?: string;
}) {
  return (
    <Figure caption={caption}>
      <div className="overflow-hidden rounded-[18px] border border-white/[0.09] bg-[#0d1118] p-4 sm:p-6">
        <p className="mb-5 text-xs font-medium uppercase tracking-[.12em] text-[#98a2b3]">
          {title}
        </p>
        <div role="img" aria-label={summary}>
          {children}
        </div>
        <p className="sr-only">{summary}</p>
      </div>
    </Figure>
  );
}
function FlowSvg({
  nodes,
  vertical = false,
  always = false,
}: {
  nodes: DiagramNode[];
  vertical?: boolean;
  always?: boolean;
}) {
  const cols = vertical ? 1 : Math.min(3, nodes.length),
    width = vertical ? 360 : 900,
    gapX = 30,
    gapY = 38,
    margin = 12;
  const cardW = (width - margin * 2 - gapX * (cols - 1)) / cols,
    cardH = 118;
  const positions = nodes.map((_, i) => {
    const row = Math.floor(i / cols),
      col = row % 2 ? cols - 1 - (i % cols) : i % cols;
    return {
      x: margin + col * (cardW + gapX),
      y: margin + row * (cardH + gapY),
    };
  });
  const height =
    Math.ceil(nodes.length / cols) * (cardH + gapY) - gapY + margin * 2;
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className={`${always ? "block" : vertical ? "sm:hidden" : "hidden sm:block"} h-auto w-full`}
      aria-hidden="true"
    >
      <title>Security review flow</title>
      {positions.slice(1).map((p, i) => {
        const prev = positions[i];
        const same = prev.y === p.y,
          forward = p.x > prev.x;
        const x1 = same ? prev.x + (forward ? cardW : 0) : prev.x + cardW / 2,
          y1 = same ? prev.y + cardH / 2 : prev.y + cardH,
          x2 = same ? p.x + (forward ? 0 : cardW) : p.x + cardW / 2,
          y2 = same ? p.y + cardH / 2 : p.y;
        return (
          <g
            key={i}
            stroke={palette.lime}
            opacity=".6"
            fill="none"
            strokeWidth="1.5"
          >
            <path d={`M${x1} ${y1} L${x2} ${y2}`} />
            {same ? (
              <path
                d={
                  forward
                    ? `M${x2 - 6} ${y2 - 4}l6 4-6 4`
                    : `M${x2 + 6} ${y2 - 4}l-6 4 6 4`
                }
              />
            ) : (
              <path d={`M${x2 - 4} ${y2 - 6}l4 6 4-6`} />
            )}
          </g>
        );
      })}
      {nodes.map((node, i) => {
        const { x, y } = positions[i],
          Icon = node.icon;
        return (
          <g key={node.title}>
            <rect
              x={x}
              y={y}
              width={cardW}
              height={cardH}
              rx="13"
              fill={palette.panel}
              stroke={node.color || "#293343"}
            />
            <text
              x={x + 18}
              y={y + 27}
              fontSize="10"
              fontFamily="monospace"
              fill={node.color || palette.lime}
            >
              {node.badge || String(i + 1).padStart(2, "0")}
            </text>
            {Icon && (
              <Icon
                x={x + cardW - 35}
                y={y + 15}
                width={20}
                height={20}
                color={node.color || palette.lime}
              />
            )}
            <text
              x={x + 18}
              y={y + 52}
              fontSize="17"
              fontWeight="600"
              fill={palette.text}
            >
              {node.title}
            </text>
            <text x={x + 18} y={y + 76} fontSize="13" fill={palette.muted}>
              {node.lines.map((line, j) => (
                <tspan key={line} x={x + 18} dy={j ? 18 : 0}>
                  {line}
                </tspan>
              ))}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
export function Flow({
  nodes,
  stacked = false,
}: {
  nodes: DiagramNode[];
  stacked?: boolean;
}) {
  return stacked ? (
    <FlowSvg nodes={nodes} vertical always />
  ) : (
    <>
      <FlowSvg nodes={nodes} />
      <FlowSvg nodes={nodes} vertical />
    </>
  );
}
export function Connector({
  label,
  color = palette.lime,
}: {
  label?: string;
  color?: string;
}) {
  return (
    <div className="flex flex-col items-center gap-1 py-3 text-[11px] text-[#98a2b3]">
      {label && <span>{label}</span>}
      <svg
        aria-hidden="true"
        width="18"
        height="24"
        viewBox="0 0 18 24"
        fill="none"
      >
        <path d="M9 1v20m-5-5 5 5 5-5" stroke={color} strokeWidth="1.5" />
      </svg>
    </div>
  );
}
export function Block({
  title,
  children,
  color = palette.lime,
}: {
  title: string;
  children: ReactNode;
  color?: string;
}) {
  return (
    <div
      className="rounded-xl border bg-[#111720] p-4"
      style={{ borderColor: `${color}40` }}
    >
      <p className="text-sm font-semibold" style={{ color }}>
        {title}
      </p>
      <div className="mt-2 text-xs leading-6 text-[#98a2b3]">{children}</div>
    </div>
  );
}
