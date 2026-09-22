import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listInvoices } from "../api";
import type { Invoice } from "../types";
import { StatusBadge } from "../components/StatusBadge";

const STATUS_FILTERS = ["all", "pending", "auto_approved", "approved", "rejected"] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

export function InvoiceListPage() {
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    listInvoices(filter === "all" ? undefined : filter)
      .then((data) => {
        if (!cancelled) setInvoices(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load invoices");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filter]);

  return (
    <section>
      <div className="toolbar">
        <h2>Invoices</h2>
        <select value={filter} onChange={(e) => setFilter(e.target.value as StatusFilter)}>
          {STATUS_FILTERS.map((f) => (
            <option key={f} value={f}>
              {f === "all" ? "All statuses" : f}
            </option>
          ))}
        </select>
      </div>

      {loading && <p className="muted">Loading...</p>}
      {error && <p className="error">{error}</p>}

      {!loading && !error && (
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Vendor</th>
              <th>Invoice #</th>
              <th>Total</th>
              <th>Fraud</th>
              <th>Status</th>
              <th>Uploaded</th>
            </tr>
          </thead>
          <tbody>
            {invoices.map((invoice) => (
              <tr key={invoice.id}>
                <td>
                  <Link to={`/invoices/${invoice.id}`}>#{invoice.id}</Link>
                </td>
                <td>{invoice.vendor_name ?? "—"}</td>
                <td>{invoice.invoice_number ?? "—"}</td>
                <td>
                  {invoice.total_amount != null
                    ? `${invoice.total_amount.toFixed(2)} ${invoice.currency ?? ""}`
                    : "—"}
                </td>
                <td>
                  {invoice.fraud_score != null ? `${invoice.fraud_score} (${invoice.fraud_level})` : "—"}
                </td>
                <td>
                  <StatusBadge status={invoice.approval_status} />
                </td>
                <td>{new Date(invoice.uploaded_at).toLocaleString()}</td>
              </tr>
            ))}
            {invoices.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  No invoices found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}
