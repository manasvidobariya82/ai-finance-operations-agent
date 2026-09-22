import { useState } from "react";
import type { GraphEdge, GraphNode, Subgraph } from "../types";

// The backend lays the graph out (spring layout, normalised to 0-1) and sends coordinates with the
// case file, so the picture is identical every time a case is reopened and no layout library is
// needed here. This component only maps that unit square onto the viewBox.
const WIDTH = 720;
const HEIGHT = 420;
const PADDING = 42;

const KIND_LABELS: Record<string, string> = {
  customer: "Customer",
  account: "Account",
  device: "Device",
  ip: "IP address",
  beneficiary: "Beneficiary",
  phone: "Shared phone",
  email: "Shared email",
  address: "Shared address",
};

function place(node: GraphNode): { cx: number; cy: number } {
  return {
    cx: PADDING + node.x * (WIDTH - 2 * PADDING),
    cy: PADDING + node.y * (HEIGHT - 2 * PADDING),
  };
}

function radiusFor(node: GraphNode): number {
  if (node.focal) return 13;
  return node.kind === "customer" || node.in_transaction ? 9 : 6;
}

function classFor(node: GraphNode): string {
  const parts = ["graph-node", `graph-node-${node.kind}`];
  if (node.focal) parts.push("graph-node-focal");
  if (node.tainted) parts.push("graph-node-tainted");
  if (node.in_transaction) parts.push("graph-node-focus");
  return parts.join(" ");
}

export function NetworkGraph({ subgraph }: { subgraph: Subgraph }) {
  const [hovered, setHovered] = useState<GraphNode | null>(null);

  if (!subgraph.nodes.length) return <p className="muted">No connected entities to draw.</p>;

  const positions = new Map(subgraph.nodes.map((node) => [node.id, place(node)]));
  const visible = (edge: GraphEdge) => positions.has(edge.source) && positions.has(edge.target);

  return (
    <div className="graph-wrap">
      <svg
        className="entity-graph"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={`Entity network: ${subgraph.nodes.length} entities, ${subgraph.edges.length} links`}
      >
        {subgraph.edges.filter(visible).map((edge, index) => {
          const from = positions.get(edge.source)!;
          const to = positions.get(edge.target)!;
          return (
            <line
              key={`${edge.source}-${edge.target}-${index}`}
              className="graph-edge"
              x1={from.cx}
              y1={from.cy}
              x2={to.cx}
              y2={to.cy}
            />
          );
        })}
        {subgraph.nodes.map((node) => {
          const { cx, cy } = positions.get(node.id)!;
          return (
            <g key={node.id} onMouseEnter={() => setHovered(node)} onMouseLeave={() => setHovered(null)}>
              <circle className={classFor(node)} cx={cx} cy={cy} r={radiusFor(node)} />
              {(node.focal || node.in_transaction || node.tainted) && (
                <text className="graph-label" x={cx} y={cy - radiusFor(node) - 6} textAnchor="middle">
                  {node.label.length > 26 ? `${node.label.slice(0, 25)}…` : node.label}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      <div className="graph-legend">
        <span className="legend-item">
          <span className="legend-swatch graph-swatch-focal" /> This customer
        </span>
        <span className="legend-item">
          <span className="legend-swatch graph-swatch-focus" /> In this transaction
        </span>
        <span className="legend-item">
          <span className="legend-swatch graph-swatch-tainted" /> Linked to confirmed fraud
        </span>
        {subgraph.truncated && <span className="muted">Showing the most relevant entities only.</span>}
      </div>

      <p className="graph-hover muted">
        {hovered
          ? `${KIND_LABELS[hovered.kind] ?? hovered.kind}: ${hovered.label} — ${hovered.hops} hop(s) away${
              hovered.tainted ? ", linked to confirmed fraud" : ""
            }`
          : "Hover a node for detail."}
      </p>
    </div>
  );
}
