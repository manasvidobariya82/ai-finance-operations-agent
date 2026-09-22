import type {
  AnalyticsSummary,
  AuditEntry,
  CaseDecision,
  CaseNote,
  DriftReport,
  FraudAlert,
  FraudAlertSummary,
  FraudCase,
  FraudCaseSummary,
  FraudDashboard,
  Invoice,
  JournalEntry,
  ModelVersion,
  ScoreResult,
} from "./types";

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // response body wasn't JSON - fall back to statusText
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export async function uploadInvoice(file: File): Promise<Invoice> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE_URL}/invoices/upload`, { method: "POST", body: formData });
  return handleResponse<Invoice>(res);
}

export async function getAnalyticsSummary(): Promise<AnalyticsSummary> {
  const res = await fetch(`${API_BASE_URL}/analytics/summary`);
  return handleResponse<AnalyticsSummary>(res);
}

export async function listInvoices(status?: string): Promise<Invoice[]> {
  const url = new URL(`${API_BASE_URL}/invoices`);
  if (status) url.searchParams.set("status", status);
  const res = await fetch(url);
  return handleResponse<Invoice[]>(res);
}

export async function getInvoice(id: number): Promise<Invoice> {
  const res = await fetch(`${API_BASE_URL}/invoices/${id}`);
  return handleResponse<Invoice>(res);
}

export async function approveInvoice(id: number, approvedBy: string): Promise<Invoice> {
  const res = await fetch(`${API_BASE_URL}/invoices/${id}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approved_by: approvedBy }),
  });
  return handleResponse<Invoice>(res);
}

export async function rejectInvoice(id: number, reason: string): Promise<Invoice> {
  const res = await fetch(`${API_BASE_URL}/invoices/${id}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
  return handleResponse<Invoice>(res);
}

export async function getJournalEntry(invoiceId: number): Promise<JournalEntry | null> {
  const res = await fetch(`${API_BASE_URL}/invoices/${invoiceId}/journal-entry`);
  if (res.status === 404) return null;
  return handleResponse<JournalEntry>(res);
}

export function journalEntryExportUrl(invoiceId: number): string {
  return `${API_BASE_URL}/invoices/${invoiceId}/journal-entry/export`;
}

export function allJournalEntriesExportUrl(): string {
  return `${API_BASE_URL}/journal-entries/export`;
}

/* --- Fraud investigation ------------------------------------------------------- */

async function postJson<T>(path: string, body: unknown = {}): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handleResponse<T>(res);
}

export async function getFraudDashboard(): Promise<FraudDashboard> {
  return handleResponse<FraudDashboard>(await fetch(`${API_BASE_URL}/fraud/dashboard`));
}

export async function listCases(params: { status?: string; priority?: string } = {}): Promise<FraudCaseSummary[]> {
  const url = new URL(`${API_BASE_URL}/fraud/cases`);
  if (params.status) url.searchParams.set("status", params.status);
  if (params.priority) url.searchParams.set("priority", params.priority);
  return handleResponse<FraudCaseSummary[]>(await fetch(url));
}

export async function getCase(caseId: string): Promise<FraudCase> {
  return handleResponse<FraudCase>(await fetch(`${API_BASE_URL}/fraud/cases/${caseId}`));
}

export async function assignCase(caseId: string, analyst: string): Promise<FraudCaseSummary> {
  return postJson<FraudCaseSummary>(`/fraud/cases/${caseId}/assign`, { analyst });
}

export async function addCaseNote(caseId: string, author: string, body: string): Promise<CaseNote> {
  return postJson<CaseNote>(`/fraud/cases/${caseId}/notes`, { author, body });
}

export async function escalateCase(caseId: string, analyst: string, reason: string): Promise<FraudCaseSummary> {
  return postJson<FraudCaseSummary>(`/fraud/cases/${caseId}/escalate`, { analyst, reason });
}

export async function decideCase(
  caseId: string,
  decision: CaseDecision,
  analyst: string,
  notes: string,
  actionsTaken: string[],
): Promise<FraudCaseSummary> {
  return postJson<FraudCaseSummary>(`/fraud/cases/${caseId}/decide`, {
    decision,
    analyst,
    notes: notes || null,
    actions_taken: actionsTaken,
  });
}

export async function listAlerts(params: { riskLevel?: string; limit?: number } = {}): Promise<FraudAlertSummary[]> {
  const url = new URL(`${API_BASE_URL}/fraud/alerts`);
  if (params.riskLevel) url.searchParams.set("risk_level", params.riskLevel);
  if (params.limit) url.searchParams.set("limit", String(params.limit));
  return handleResponse<FraudAlertSummary[]>(await fetch(url));
}

export async function getAlert(alertId: string): Promise<FraudAlert> {
  return handleResponse<FraudAlert>(await fetch(`${API_BASE_URL}/fraud/alerts/${alertId}`));
}

export async function generateFraudData(customers: number, days: number): Promise<Record<string, unknown>> {
  return postJson(`/fraud/data/generate`, { customers, days, reset: true });
}

export async function trainModel(notes?: string): Promise<ModelVersion> {
  return postJson<ModelVersion>(`/fraud/model/train`, { notes: notes ?? null, activate: true });
}

export async function listModelVersions(): Promise<ModelVersion[]> {
  return handleResponse<ModelVersion[]>(await fetch(`${API_BASE_URL}/fraud/model/versions`));
}

export async function activateModelVersion(version: string): Promise<ModelVersion> {
  return postJson<ModelVersion>(`/fraud/model/versions/${version}/activate`);
}

export async function getDriftReport(): Promise<DriftReport> {
  return handleResponse<DriftReport>(await fetch(`${API_BASE_URL}/fraud/model/drift`));
}

export async function scoreBacklog(): Promise<ScoreResult> {
  return postJson<ScoreResult>(`/fraud/score`, {});
}

export async function listAudit(entityId?: string): Promise<AuditEntry[]> {
  const url = new URL(`${API_BASE_URL}/fraud/audit`);
  if (entityId) url.searchParams.set("entity_id", entityId);
  return handleResponse<AuditEntry[]>(await fetch(url));
}

export async function verifyAudit(): Promise<{ valid: boolean; entries_checked: number; first_invalid_id: number | null }> {
  return handleResponse(await fetch(`${API_BASE_URL}/fraud/audit/verify`));
}
