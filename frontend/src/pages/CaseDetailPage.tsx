import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { addCaseNote, assignCase, decideCase, escalateCase, getCase } from "../api";
import { NetworkGraph } from "../components/NetworkGraph";
import { RiskBadge } from "../components/RiskBadge";
import type { CaseDecision, FraudCase, RankedHypothesis, RiskLevel, Subgraph } from "../types";

const DECISIONS: { value: CaseDecision; label: string; hint: string }[] = [
  { value: "fraud_confirmed", label: "Confirmed fraud", hint: "Labels the transaction as fraud for the next model." },
  { value: "false_positive", label: "False positive", hint: "Labels it as legitimate for the next model." },
  { value: "inconclusive", label: "Inconclusive", hint: "Stores no label - the model learns nothing from this." },
];

const SECTION_HINTS: Record<string, string> = {
  evidence: "What happened, and which features moved the score.",
  behavior: "What is normal for this customer, and what changed.",
  intel: "Watchlists, IP reputation and counterparty standing.",
  network: "Who else is connected to these entities.",
  history: "Whether this customer, or this signal pattern, has been seen before.",
  hypothesis: "Which fraud typology fits the evidence.",
  recommendation: "What to consider doing, and why.",
  narrative: "The written summary.",
};

function severityForRisk(level: RiskLevel): "good" | "warning" | "critical" {
  if (level === "low") return "good";
  return level === "high" ? "critical" : "warning";
}

function formatDate(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "-";
}

function HypothesisBar({ hypothesis, primary }: { hypothesis: RankedHypothesis; primary: boolean }) {
  return (
    <div className={`hypothesis ${primary ? "hypothesis-primary" : ""}`}>
      <div className="meter-row">
        <span className="meter-caption">{hypothesis.label}</span>
        <div className="meter-track">
          <div
            className={`meter-fill ${primary ? "meter-critical" : "meter-warning"}`}
            style={{ width: `${Math.round(hypothesis.support * 100)}%` }}
          />
        </div>
        <span className="meter-value">{Math.round(hypothesis.support * 100)}%</span>
      </div>
      {primary && (
        <div className="hypothesis-detail">
          <p className="muted">{hypothesis.description}</p>
          {hypothesis.matched.length > 0 && (
            <>
              <h4>Supported by</h4>
              <ul>
                {hypothesis.matched.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </>
          )}
          {hypothesis.against.length > 0 && (
            <>
              <h4>Argues against</h4>
              <ul className="issues">
                {hypothesis.against.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </>
          )}
          {hypothesis.missing.length > 0 && (
            <>
              <h4>Not seen</h4>
              <ul className="muted">
                {hypothesis.missing.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export function CaseDetailPage() {
  const { id = "" } = useParams();
  const [fraudCase, setFraudCase] = useState<FraudCase | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [analyst, setAnalyst] = useState("");
  const [decision, setDecision] = useState<CaseDecision>("fraud_confirmed");
  const [decisionNotes, setDecisionNotes] = useState("");
  const [chosenActions, setChosenActions] = useState<string[]>([]);
  const [noteBody, setNoteBody] = useState("");
  const [openSection, setOpenSection] = useState<string | null>("evidence");

  const load = useCallback(async () => setFraudCase(await getCase(id)), [id]);

  useEffect(() => {
    load().catch((err) => setError(err instanceof Error ? err.message : "Failed to load case"));
  }, [load]);

  async function run(task: () => Promise<unknown>) {
    if (!analyst.trim()) {
      setError("Enter your name first - every action is recorded against an analyst.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await task();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  if (error && !fraudCase) return <p className="error">{error}</p>;
  if (!fraudCase) return <p className="muted">Loading...</p>;

  const file = fraudCase.case_file;
  const closed = fraudCase.status === "closed";
  const networkSection = file.sections.find((section) => section.agent === "network");
  const subgraph = networkSection?.data?.subgraph as Subgraph | undefined;

  return (
    <section className="detail">
      <div className="detail-header">
        <div>
          <h2>
            {fraudCase.id} <RiskBadge level={fraudCase.risk_level} score={fraudCase.risk_score} />
          </h2>
          <p className="muted">
            Customer {fraudCase.customer_id} · transaction {fraudCase.transaction_id} · opened{" "}
            {formatDate(fraudCase.created_at)} · {fraudCase.priority} priority
            {fraudCase.assigned_to ? ` · assigned to ${fraudCase.assigned_to}` : " · unassigned"}
          </p>
        </div>
        <Link className="button" to="/fraud/cases">
          Back to queue
        </Link>
      </div>

      {error && <p className="error">{error}</p>}

      {closed && (
        <div className="card card-closed">
          <h3>Decided: {fraudCase.decision?.replace(/_/g, " ")}</h3>
          <p className="muted">
            By {fraudCase.decided_by} on {formatDate(fraudCase.decided_at)}
          </p>
          {fraudCase.decision_notes && <p>{fraudCase.decision_notes}</p>}
          {fraudCase.actions.length > 0 && (
            <>
              <h4>Actions</h4>
              <ul>
                {fraudCase.actions.map((action) => (
                  <li key={action.action}>
                    {action.effect ?? action.action.replace(/_/g, " ")}
                    {!action.executed_here && <span className="muted"> — to be carried out outside this system</span>}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      <div className="card">
        <h3>{file.headline ?? "Case summary"}</h3>
        <p>{file.summary}</p>
        {file.key_points.length > 0 && (
          <ul>
            {file.key_points.map((point) => (
              <li key={point}>{point}</li>
            ))}
          </ul>
        )}
        <p className="muted">
          Risk {file.risk.score}/100 ({file.risk.level}) — {file.risk.method_explanation}.
          {file.narrative_source === "deterministic" && " Summary written without the language model."}
          {file.model_version && ` Model ${file.model_version}.`}
        </p>
        <div className="meter-row">
          <span className="meter-caption">Risk score</span>
          <div className="meter-track">
            <div
              className={`meter-fill meter-${severityForRisk(file.risk.level)}`}
              style={{ width: `${file.risk.score}%` }}
            />
          </div>
          <span className="meter-value">{file.risk.score}</span>
        </div>
      </div>

      <div className="grid">
        <div className="card">
          <h3>Detector contributions</h3>
          <table className="table">
            <thead>
              <tr>
                <th>Detector</th>
                <th>Score</th>
                <th>Weight</th>
              </tr>
            </thead>
            <tbody>
              {file.risk.breakdown.map((item) => (
                <tr key={item.component}>
                  <td>{item.label}</td>
                  <td>{item.score.toFixed(2)}</td>
                  <td>{(item.weight * 100).toFixed(0)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h3>Checks that would settle it</h3>
          {file.verification_steps.length ? (
            <ul>
              {file.verification_steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          ) : (
            <p className="muted">None suggested.</p>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Hypotheses</h3>
        {file.primary_hypothesis ? (
          file.hypotheses
            .filter((item) => item.support > 0 || item.label === file.primary_hypothesis)
            .map((item) => (
              <HypothesisBar key={item.id} hypothesis={item} primary={item.label === file.primary_hypothesis} />
            ))
        ) : (
          <p className="muted">
            No fraud typology fits the evidence strongly enough to name one; the alert rests on the risk score.
          </p>
        )}
      </div>

      {subgraph && (
        <div className="card">
          <h3>Entity network</h3>
          <p className="muted">{networkSection?.summary}</p>
          <NetworkGraph subgraph={subgraph} />
        </div>
      )}

      <div className="card">
        <h3>Investigation</h3>
        <p className="muted">
          Each section was produced by one agent and recorded in the audit trail under its own name.
        </p>
        {file.sections.map((section) => (
          <div key={section.agent} className="section-block">
            <button
              className="section-toggle"
              onClick={() => setOpenSection(openSection === section.agent ? null : section.agent)}
            >
              <span>
                <strong>{section.title}</strong>
                <span className="muted"> — {section.summary}</span>
              </span>
              <span className="muted">{openSection === section.agent ? "−" : "+"}</span>
            </button>
            {openSection === section.agent && (
              <div className="section-body">
                <p className="muted">{SECTION_HINTS[section.agent]}</p>
                {section.findings.length ? (
                  <ul>
                    {section.findings.map((finding, index) => (
                      <li key={`${section.agent}-${index}`}>{finding}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="muted">Nothing to report.</p>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {!closed && (
        <div className="card">
          <h3>Decide</h3>
          <p className="muted">
            Nothing has been done to the account yet. Only the actions you tick are carried out, and every one
            of them is recorded against your name.
          </p>

          <label className="field">
            <span>Your name</span>
            <input value={analyst} onChange={(event) => setAnalyst(event.target.value)} placeholder="analyst" />
          </label>

          <h4>Recommended actions</h4>
          <ul className="action-list">
            {file.recommended_actions.map((action) => (
              <li key={action.action}>
                <label>
                  <input
                    type="checkbox"
                    checked={chosenActions.includes(action.action)}
                    onChange={(event) =>
                      setChosenActions((previous) =>
                        event.target.checked
                          ? [...previous, action.action]
                          : previous.filter((item) => item !== action.action),
                      )
                    }
                  />
                  <strong>{action.label}</strong>
                  {action.urgency === "immediate" && <span className="badge badge-risk-high">Before funds move</span>}
                  <span className="muted"> — {action.rationale}</span>
                </label>
              </li>
            ))}
          </ul>

          <label className="field">
            <span>Decision</span>
            <select value={decision} onChange={(event) => setDecision(event.target.value as CaseDecision)}>
              {DECISIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <p className="muted">{DECISIONS.find((option) => option.value === decision)?.hint}</p>

          <label className="field">
            <span>Notes</span>
            <textarea
              value={decisionNotes}
              onChange={(event) => setDecisionNotes(event.target.value)}
              rows={3}
              placeholder="What did you find?"
            />
          </label>

          <div className="action-row">
            <button
              className="button"
              disabled={busy}
              onClick={() => run(() => decideCase(fraudCase.id, decision, analyst, decisionNotes, chosenActions))}
            >
              {busy ? "Saving..." : "Close case"}
            </button>
            <button className="button" disabled={busy} onClick={() => run(() => assignCase(fraudCase.id, analyst))}>
              Assign to me
            </button>
            <button
              className="button"
              disabled={busy || !decisionNotes.trim()}
              onClick={() => run(() => escalateCase(fraudCase.id, analyst, decisionNotes))}
            >
              Escalate (uses notes as the reason)
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <h3>Notes</h3>
        {fraudCase.notes.length ? (
          <ul className="note-list">
            {fraudCase.notes.map((note) => (
              <li key={note.id}>
                <span className="muted">
                  {note.author} · {formatDate(note.created_at)}
                </span>
                <p>{note.body}</p>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">No notes yet.</p>
        )}
        <label className="field">
          <span>Add a note</span>
          <textarea value={noteBody} onChange={(event) => setNoteBody(event.target.value)} rows={2} />
        </label>
        <div className="action-row">
          <button
            className="button"
            disabled={busy || !noteBody.trim()}
            onClick={() =>
              run(async () => {
                await addCaseNote(fraudCase.id, analyst, noteBody);
                setNoteBody("");
              })
            }
          >
            Add note
          </button>
        </div>
      </div>
    </section>
  );
}
