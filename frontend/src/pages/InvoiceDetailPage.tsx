import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  approveInvoice,
  getInvoice,
  getJournalEntry,
  journalEntryExportUrl,
  rejectInvoice,
} from "../api";
import type { Invoice, JournalEntry } from "../types";
import { StatusBadge } from "../components/StatusBadge";

export function InvoiceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const invoiceId = Number(id);

  const [invoice, setInvoice] = useState<Invoice | null>(null);
  const [journalEntry, setJournalEntry] = useState<JournalEntry | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [approvedBy, setApprovedBy] = useState("");
  const [rejectionReason, setRejectionReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const inv = await getInvoice(invoiceId);
      setInvoice(inv);
      if (inv.approval_status === "approved" || inv.approval_status === "auto_approved") {
        setJournalEntry(await getJournalEntry(invoiceId));
      } else {
        setJournalEntry(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load invoice");
    } finally {
      setLoading(false);
    }
  }, [invoiceId]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleApprove() {
    if (!approvedBy.trim()) {
      setActionError("Enter your name to approve.");
      return;
    }
    setSubmitting(true);
    setActionError(null);
    try {
      await approveInvoice(invoiceId, approvedBy.trim());
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Approval failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleReject() {
    if (!rejectionReason.trim()) {
      setActionError("Enter a reason to reject.");
      return;
    }
    setSubmitting(true);
    setActionError(null);
    try {
      await rejectInvoice(invoiceId, rejectionReason.trim());
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Rejection failed");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <p className="muted">Loading...</p>;
  if (error) return <p className="error">{error}</p>;
  if (!invoice) return null;

  return (
    <section className="detail">
      <div className="detail-header">
        <h2>
          Invoice #{invoice.id} <StatusBadge status={invoice.approval_status} />
        </h2>
        <span className="muted">Pipeline stage: {invoice.status}</span>
      </div>

      <div className="grid">
        <div className="card">
          <h3>Vendor & Amounts</h3>
          <dl>
            <dt>Vendor</dt>
            <dd>{invoice.vendor_name ?? "—"}</dd>
            <dt>Invoice #</dt>
            <dd>{invoice.invoice_number ?? "—"}</dd>
            <dt>Invoice date</dt>
            <dd>{invoice.invoice_date ?? "—"}</dd>
            <dt>Due date</dt>
            <dd>{invoice.due_date ?? "—"}</dd>
            <dt>PO number</dt>
            <dd>{invoice.po_number ?? "—"}</dd>
            <dt>Subtotal</dt>
            <dd>{invoice.subtotal ?? "—"}</dd>
            <dt>Tax</dt>
            <dd>{invoice.tax_amount ?? "—"}</dd>
            <dt>Total</dt>
            <dd>
              {invoice.total_amount ?? "—"} {invoice.currency}
            </dd>
            <dt>Extraction confidence</dt>
            <dd>
              {invoice.extraction_confidence != null
                ? `${Math.round(invoice.extraction_confidence * 100)}%`
                : "—"}
            </dd>
          </dl>
        </div>

        <div className="card">
          <h3>Risk & Compliance</h3>
          <dl>
            <dt>Validation</dt>
            <dd>
              {invoice.validation_errors && invoice.validation_errors.length > 0 ? (
                <ul className="issues">
                  {invoice.validation_errors.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              ) : (
                "No issues"
              )}
            </dd>
            <dt>Duplicate</dt>
            <dd>{invoice.is_duplicate ? `Yes — ${invoice.duplicate_reason}` : "No"}</dd>
            <dt>Fraud score</dt>
            <dd>
              {invoice.fraud_score != null ? `${invoice.fraud_score}/100 (${invoice.fraud_level})` : "—"}
            </dd>
            <dt>Fraud reasons</dt>
            <dd>
              {invoice.fraud_reasons && invoice.fraud_reasons.length > 0 ? (
                <ul className="issues">
                  {invoice.fraud_reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              ) : (
                "None"
              )}
            </dd>
          </dl>
        </div>
      </div>

      {invoice.line_items && invoice.line_items.length > 0 && (
        <div className="card">
          <h3>Line Items</h3>
          <table className="table">
            <thead>
              <tr>
                <th>Description</th>
                <th>Qty</th>
                <th>Unit Price</th>
                <th>Amount</th>
              </tr>
            </thead>
            <tbody>
              {invoice.line_items.map((item, i) => (
                <tr key={i}>
                  <td>{item.description}</td>
                  <td>{item.quantity}</td>
                  <td>{item.unit_price}</td>
                  <td>{item.amount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {invoice.approval_status === "pending" && (
        <div className="card">
          <h3>Review Decision</h3>
          <div className="action-row">
            <input
              type="text"
              placeholder="Your name (approver)"
              value={approvedBy}
              onChange={(e) => setApprovedBy(e.target.value)}
            />
            <button onClick={handleApprove} disabled={submitting}>
              Approve
            </button>
          </div>
          <div className="action-row">
            <input
              type="text"
              placeholder="Rejection reason"
              value={rejectionReason}
              onChange={(e) => setRejectionReason(e.target.value)}
            />
            <button className="danger" onClick={handleReject} disabled={submitting}>
              Reject
            </button>
          </div>
          {actionError && <p className="error">{actionError}</p>}
        </div>
      )}

      {invoice.approval_status === "rejected" && invoice.rejection_reason && (
        <div className="card">
          <h3>Rejection</h3>
          <p>{invoice.rejection_reason}</p>
        </div>
      )}

      {(invoice.approval_status === "approved" || invoice.approval_status === "auto_approved") && (
        <div className="card">
          <h3>Journal Entry</h3>
          {invoice.approved_by && (
            <p className="muted">
              Approved by {invoice.approved_by} at{" "}
              {invoice.approved_at ? new Date(invoice.approved_at).toLocaleString() : "—"}
            </p>
          )}
          {journalEntry ? (
            <>
              <table className="table">
                <thead>
                  <tr>
                    <th>Account</th>
                    <th>Debit</th>
                    <th>Credit</th>
                    <th>Memo</th>
                  </tr>
                </thead>
                <tbody>
                  {journalEntry.lines.map((line, i) => (
                    <tr key={i}>
                      <td>{line.account}</td>
                      <td>{line.debit ? line.debit.toFixed(2) : ""}</td>
                      <td>{line.credit ? line.credit.toFixed(2) : ""}</td>
                      <td>{line.memo}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <a className="button" href={journalEntryExportUrl(invoice.id)}>
                Export CSV
              </a>
            </>
          ) : (
            <p className="muted">Loading journal entry...</p>
          )}
        </div>
      )}
    </section>
  );
}
