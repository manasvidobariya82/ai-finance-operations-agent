import type { RiskLevel } from "../types";

const LABELS: Record<RiskLevel, string> = {
  low: "Low risk",
  medium: "Medium risk",
  high: "High risk",
};

export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  return (
    <span className={`badge badge-risk-${level}`}>
      {LABELS[level]}
      {score != null ? ` · ${score}` : ""}
    </span>
  );
}
