import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listCases } from "../api";
import { RiskBadge } from "../components/RiskBadge";
import type { CaseStatus, FraudCaseSummary } from "../types";

const FILTERS: { label: string; status?: CaseStatus }[] = [
  { label: "Open", status: "open" },
  { label: "Escalated", status: "escalated" },
  { label: "Closed", status: "closed" },
  { label: "All" },
];

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "-";
}

export function CaseQueuePage() {
  const [cases, setCases] = useState<FraudCaseSummary[]>([]);
  const [filter, setFilter] = useState<CaseStatus | undefined>("open");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    listCases({ status: filter })
      .then((rows) => {
        if (!cancelled) setCases(rows);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load cases");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filter]);

  return (
    <section className="detail">
      <div className="detail-header">
        <h2>Case queue</h2>
        <Link className="button" to="/fraud">
          Fraud dashboard
        </Link>
      </div>

      <div className="toolbar">
        {FILTERS.map((option) => (
          <button
            key={option.label}
            className={`button ${filter === option.status ? "button-active" : ""}`}
            onClick={() => setFilter(option.status)}
          >
            {option.label}
          </button>
        ))}
      </div>

      {error && <p className="error">{error}</p>}
      {loading ? (
        <p className="muted">Loading...</p>
      ) : cases.length === 0 ? (
        <p className="muted">No cases in this view.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Case</th>
              <th>Risk</th>
              <th>Hypothesis</th>
              <th>Customer</th>
              <th>Opened</th>
              <th>Assigned</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {cases.map((row) => (
              <tr key={row.id}>
                <td>
                  <Link to={`/fraud/cases/${row.id}`}>{row.id}</Link>
                  {row.alert_ids.length > 1 && (
                    <span className="muted"> · {row.alert_ids.length} alerts</span>
                  )}
                </td>
                <td>
                  <RiskBadge level={row.risk_level} score={row.risk_score} />
                </td>
                <td>{row.primary_hypothesis ?? <span className="muted">Not classified</span>}</td>
                <td>{row.customer_id}</td>
                <td>{formatDate(row.created_at)}</td>
                <td>{row.assigned_to ?? <span className="muted">Unassigned</span>}</td>
                <td>
                  {row.decision ? (
                    <span className={`badge badge-decision-${row.decision}`}>{row.decision.replace(/_/g, " ")}</span>
                  ) : (
                    <span className={`badge badge-case-${row.status}`}>{row.status.replace(/_/g, " ")}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="muted">
        Cases are ordered by risk, then by age - the order they should be worked in. Medium and high risk
        alerts reach this queue; low risk ones are auto-closed and kept for measurement.
      </p>
    </section>
  );
}
