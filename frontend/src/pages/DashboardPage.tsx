import { useEffect, useState } from "react";
import { getAnalyticsSummary } from "../api";
import type { AnalyticsSummary } from "../types";

// Mirrors the backend's default AUTO_APPROVE_MAX_RISK_SCORE / MANDATORY_REVIEW_RISK_SCORE.
const RISK_LOW_MAX = 20;
const RISK_HIGH_MIN = 80;

function severityForScore(score: number): "good" | "warning" | "critical" {
  if (score <= RISK_LOW_MAX) return "good";
  if (score >= RISK_HIGH_MIN) return "critical";
  return "warning";
}

function formatAmount(amount: number): string {
  return amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat-tile">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

export function DashboardPage() {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getAnalyticsSummary()
      .then((data) => {
        if (!cancelled) setSummary(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load analytics");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <p className="muted">Loading...</p>;
  if (error) return <p className="error">{error}</p>;
  if (!summary) return null;

  const fraudTotal =
    summary.fraud_level_counts.low + summary.fraud_level_counts.medium + summary.fraud_level_counts.high;
  const currencies = Array.from(
    new Set([
      ...Object.keys(summary.spend_by_currency),
      ...Object.keys(summary.pending_amount_by_currency),
      ...Object.keys(summary.rejected_amount_by_currency),
    ]),
  ).sort();

  const scoreSeverity = summary.average_fraud_score != null ? severityForScore(summary.average_fraud_score) : null;

  return (
    <section className="detail">
      <h2>Dashboard</h2>

      <div className="stat-grid">
        <StatTile label="Total invoices" value={summary.total_invoices} />
        <StatTile label="Pending review" value={summary.pending_review} />
        <StatTile label="Auto-approved" value={summary.auto_approved} />
        <StatTile label="Approved" value={summary.approved} />
        <StatTile label="Rejected" value={summary.rejected} />
        <StatTile label="Duplicates flagged" value={summary.duplicate_count} />
      </div>

      <div className="card">
        <h3>Fraud risk</h3>

        {summary.average_fraud_score != null && scoreSeverity ? (
          <div className="meter-row" title={`Average fraud score: ${summary.average_fraud_score.toFixed(1)} / 100`}>
            <span className="meter-caption">Average fraud score</span>
            <div className="meter-track">
              <div
                className={`meter-fill meter-${scoreSeverity}`}
                style={{ width: `${Math.min(100, Math.max(0, summary.average_fraud_score))}%` }}
              />
            </div>
            <span className="meter-value">{summary.average_fraud_score.toFixed(0)}/100</span>
          </div>
        ) : (
          <p className="muted">No scored invoices yet.</p>
        )}

        {fraudTotal > 0 && (
          <div className="fraud-breakdown">
            <div className="stacked-bar">
              {summary.fraud_level_counts.low > 0 && (
                <div
                  className="stacked-bar-segment severity-good"
                  style={{ width: `${(summary.fraud_level_counts.low / fraudTotal) * 100}%` }}
                  title={`Low risk: ${summary.fraud_level_counts.low}`}
                />
              )}
              {summary.fraud_level_counts.medium > 0 && (
                <div
                  className="stacked-bar-segment severity-warning"
                  style={{ width: `${(summary.fraud_level_counts.medium / fraudTotal) * 100}%` }}
                  title={`Medium risk: ${summary.fraud_level_counts.medium}`}
                />
              )}
              {summary.fraud_level_counts.high > 0 && (
                <div
                  className="stacked-bar-segment severity-critical"
                  style={{ width: `${(summary.fraud_level_counts.high / fraudTotal) * 100}%` }}
                  title={`High risk: ${summary.fraud_level_counts.high}`}
                />
              )}
            </div>
            <div className="legend">
              <span className="legend-item">
                <span className="legend-swatch severity-good" /> Low risk ({summary.fraud_level_counts.low})
              </span>
              <span className="legend-item">
                <span className="legend-swatch severity-warning" /> Medium risk ({summary.fraud_level_counts.medium})
              </span>
              <span className="legend-item">
                <span className="legend-swatch severity-critical" /> High risk ({summary.fraud_level_counts.high})
              </span>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Spend by currency</h3>
        {currencies.length === 0 ? (
          <p className="muted">No invoice amounts recorded yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Currency</th>
                <th>Approved spend</th>
                <th>Pending</th>
                <th>Rejected</th>
              </tr>
            </thead>
            <tbody>
              {currencies.map((currency) => (
                <tr key={currency}>
                  <td>{currency}</td>
                  <td className="num">{formatAmount(summary.spend_by_currency[currency] ?? 0)}</td>
                  <td className="num">{formatAmount(summary.pending_amount_by_currency[currency] ?? 0)}</td>
                  <td className="num">{formatAmount(summary.rejected_amount_by_currency[currency] ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
