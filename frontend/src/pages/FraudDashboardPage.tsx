import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  generateFraudData,
  getDriftReport,
  getFraudDashboard,
  listModelVersions,
  scoreBacklog,
  trainModel,
  verifyAudit,
} from "../api";
import type { DriftReport, FraudDashboard, ModelVersion } from "../types";

const DRIFT_LABELS: Record<string, string> = {
  stable: "Stable",
  moderate_shift: "Moderate shift",
  significant_shift: "Significant shift - retrain",
};

function formatAmount(amount: number): string {
  return `₹${amount.toLocaleString("en-IN", { maximumFractionDigits: 0 })}`;
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat-tile">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

export function FraudDashboardPage() {
  const [dashboard, setDashboard] = useState<FraudDashboard | null>(null);
  const [versions, setVersions] = useState<ModelVersion[]>([]);
  const [drift, setDrift] = useState<DriftReport | null>(null);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [summary, modelVersions, driftReport, audit] = await Promise.all([
      getFraudDashboard(),
      listModelVersions(),
      getDriftReport(),
      verifyAudit(),
    ]);
    setDashboard(summary);
    setVersions(modelVersions);
    setDrift(driftReport);
    setAuditValid(audit.valid);
  }, []);

  useEffect(() => {
    refresh().catch((err) => setError(err instanceof Error ? err.message : "Failed to load"));
  }, [refresh]);

  async function run(label: string, task: () => Promise<string>) {
    setBusy(label);
    setError(null);
    setNotice(null);
    try {
      setNotice(await task());
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Operation failed");
    } finally {
      setBusy(null);
    }
  }

  if (error && !dashboard) return <p className="error">{error}</p>;
  if (!dashboard) return <p className="muted">Loading...</p>;

  const alerts = dashboard.alerts_by_level;
  const feedback = dashboard.feedback;
  const metrics = dashboard.model_metrics;

  return (
    <section className="detail">
      <div className="detail-header">
        <h2>Fraud operations</h2>
        <Link className="button" to="/fraud/cases">
          Open case queue
        </Link>
      </div>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {!dashboard.data_available ? (
        <div className="card">
          <h3>No transaction data yet</h3>
          <p className="muted">
            The fraud module works on a generated bank: customers, 90 days of traffic and injected fraud
            scenarios. Generate it, train a model on the labelled history, then score the backlog.
          </p>
          <div className="action-row">
            <button
              className="button"
              disabled={busy !== null}
              onClick={() =>
                run("generate", async () => {
                  const result = await generateFraudData(120, 90);
                  return `Generated ${result.transactions} transactions for ${result.customers} customers.`;
                })
              }
            >
              {busy === "generate" ? "Generating..." : "Generate data"}
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="stat-grid">
            <StatTile label="Customers" value={dashboard.customers.toLocaleString()} />
            <StatTile label="Transactions" value={dashboard.transactions.toLocaleString()} />
            <StatTile label="Scored" value={dashboard.scored_transactions.toLocaleString()} />
            <StatTile label="Open cases" value={dashboard.open_cases} />
            <StatTile label="Closed cases" value={dashboard.closed_cases} />
            <StatTile label="Amount at risk" value={formatAmount(dashboard.amount_at_risk)} />
          </div>

          <div className="card">
            <h3>Pipeline</h3>
            <p className="muted">
              {dashboard.unscored_transactions > 0
                ? `${dashboard.unscored_transactions.toLocaleString()} transaction(s) have not been scored yet.`
                : "Every transaction has been scored."}
            </p>
            <div className="action-row">
              <button
                className="button"
                disabled={busy !== null}
                onClick={() =>
                  run("train", async () => {
                    const version = await trainModel("Trained from the console");
                    return `Trained and activated ${version.version} on ${version.training_rows.toLocaleString()} rows.`;
                  })
                }
              >
                {busy === "train" ? "Training..." : "Train model"}
              </button>
              <button
                className="button"
                disabled={busy !== null || dashboard.unscored_transactions === 0}
                onClick={() =>
                  run("score", async () => {
                    const result = await scoreBacklog();
                    return `Scored ${result.scored.toLocaleString()} transactions: ${result.cases} case(s) opened, ${result.auto_closed.toLocaleString()} auto-closed.`;
                  })
                }
              >
                {busy === "score" ? "Scoring..." : "Score backlog"}
              </button>
            </div>
            {busy === "score" && (
              <p className="muted">Scoring the whole backlog runs every detector over every transaction; this takes a while.</p>
            )}
          </div>

          <div className="grid">
            <div className="card">
              <h3>Alerts by risk</h3>
              <table className="table">
                <tbody>
                  <tr>
                    <td>High</td>
                    <td>{(alerts.high ?? 0).toLocaleString()}</td>
                  </tr>
                  <tr>
                    <td>Medium</td>
                    <td>{(alerts.medium ?? 0).toLocaleString()}</td>
                  </tr>
                  <tr>
                    <td>Low (auto-closed)</td>
                    <td>{(alerts.low ?? 0).toLocaleString()}</td>
                  </tr>
                </tbody>
              </table>
              <p className="muted">
                Low-risk alerts are kept rather than discarded: they are the denominator for measuring
                precision later.
              </p>
            </div>

            <div className="card">
              <h3>Cases by hypothesis</h3>
              {Object.keys(dashboard.cases_by_hypothesis).length ? (
                <table className="table">
                  <tbody>
                    {Object.entries(dashboard.cases_by_hypothesis)
                      .sort((a, b) => b[1] - a[1])
                      .map(([name, count]) => (
                        <tr key={name}>
                          <td>{name}</td>
                          <td>{count}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              ) : (
                <p className="muted">No cases opened yet.</p>
              )}
            </div>
          </div>

          <div className="card">
            <h3>Model</h3>
            {dashboard.active_model ? (
              <>
                <p>
                  Active: <code>{dashboard.active_model}</code>
                  {drift?.available && (
                    <>
                      {" · drift "}
                      <span className={drift.retrain_recommended ? "severity-critical" : "severity-good"}>
                        {DRIFT_LABELS[drift.status ?? ""] ?? drift.status} (PSI {drift.max_psi})
                      </span>
                    </>
                  )}
                </p>
                {metrics && (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>ROC AUC</th>
                        <th>PR AUC</th>
                        <th>Precision</th>
                        <th>Recall</th>
                        <th>Alert rate</th>
                        <th>Holdout</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{String(metrics.roc_auc ?? "-")}</td>
                        <td>{String(metrics.pr_auc ?? "-")}</td>
                        <td>{String(metrics.precision ?? "-")}</td>
                        <td>{String(metrics.recall ?? "-")}</td>
                        <td>{String(metrics.alert_rate ?? "-")}</td>
                        <td>{String(metrics.holdout ?? "-")}</td>
                      </tr>
                    </tbody>
                  </table>
                )}
                {versions.length > 1 && (
                  <p className="muted">{versions.length} versions registered; the newest is active.</p>
                )}
              </>
            ) : (
              <p className="muted">
                No model trained yet. The rule, behaviour and graph detectors still run; the ML and anomaly
                components drop out and the remaining weights are renormalised.
              </p>
            )}
          </div>

          <div className="grid">
            <div className="card">
              <h3>Analyst feedback</h3>
              {feedback.labelled ? (
                <table className="table">
                  <tbody>
                    <tr>
                      <td>Decisions recorded</td>
                      <td>{feedback.total_decisions}</td>
                    </tr>
                    <tr>
                      <td>Confirmed fraud</td>
                      <td>{feedback.confirmed_fraud}</td>
                    </tr>
                    <tr>
                      <td>False positives</td>
                      <td>{feedback.false_positives}</td>
                    </tr>
                    <tr>
                      <td>Precision</td>
                      <td>{feedback.precision != null ? `${(feedback.precision * 100).toFixed(0)}%` : "-"}</td>
                    </tr>
                  </tbody>
                </table>
              ) : (
                <p className="muted">No cases have been decided yet. Decisions become training labels.</p>
              )}
            </div>

            <div className="card">
              <h3>Audit trail</h3>
              <p>
                {dashboard.audit_entries.toLocaleString()} entries ·{" "}
                {auditValid == null ? (
                  "checking"
                ) : auditValid ? (
                  <span className="severity-good">hash chain verified</span>
                ) : (
                  <span className="severity-critical">chain broken - an entry was altered</span>
                )}
              </p>
              <p className="muted">
                Every entry's hash covers the previous one, so editing or deleting history is detectable.
              </p>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
