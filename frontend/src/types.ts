export interface LineItem {
  description: string;
  quantity: number;
  unit_price: number;
  amount: number;
}

export type ApprovalStatus = "pending" | "auto_approved" | "approved" | "rejected";
export type FraudLevel = "low" | "medium" | "high";

export interface Invoice {
  id: number;
  filename: string;
  status: string;
  uploaded_at: string;

  vendor_name: string | null;
  vendor_address: string | null;
  vendor_tax_id: string | null;
  invoice_number: string | null;
  invoice_date: string | null;
  due_date: string | null;
  po_number: string | null;
  currency: string | null;
  subtotal: number | null;
  tax_amount: number | null;
  total_amount: number | null;
  line_items: LineItem[] | null;
  bank_account_last4: string | null;
  extraction_confidence: number | null;
  uncertain_fields: string[] | null;

  validation_errors: string[] | null;

  is_duplicate: boolean;
  duplicate_of_id: number | null;
  duplicate_reason: string | null;

  fraud_score: number | null;
  fraud_level: FraudLevel | null;
  fraud_reasons: string[] | null;
  fraud_rule_flags: string[] | null;

  approval_status: ApprovalStatus;
  approved_by: string | null;
  approved_at: string | null;
  rejection_reason: string | null;
}

export interface JournalEntryLine {
  account: string;
  debit: number;
  credit: number;
  memo: string;
}

export interface JournalEntry {
  id: number;
  invoice_id: number;
  entry_date: string;
  lines: JournalEntryLine[];
  currency: string;
  total_amount: number;
  posted_at: string;
}

export interface FraudLevelCounts {
  low: number;
  medium: number;
  high: number;
}

export interface AnalyticsSummary {
  total_invoices: number;
  pending_review: number;
  auto_approved: number;
  approved: number;
  rejected: number;
  duplicate_count: number;
  average_fraud_score: number | null;
  fraud_level_counts: FraudLevelCounts;
  spend_by_currency: Record<string, number>;
  pending_amount_by_currency: Record<string, number>;
  rejected_amount_by_currency: Record<string, number>;
}

/* --- Fraud investigation ------------------------------------------------------- */

export type RiskLevel = "low" | "medium" | "high";
export type CaseStatus = "open" | "pending_verification" | "escalated" | "closed";
export type CaseDecision = "fraud_confirmed" | "false_positive" | "inconclusive";

export interface RiskSignal {
  code: string;
  severity: "low" | "medium" | "high";
  description: string;
  value: number | null;
}

export interface RuleHit {
  id: string;
  name: string;
  severity: string;
  weight: number;
  floor: number;
}

export interface DetectorContribution {
  component: string;
  label: string;
  score: number;
  weight: number;
  contribution: number;
}

export interface FeatureContribution {
  feature: string;
  label: string;
  value: number;
  contribution: number;
}

export interface FraudAlertSummary {
  id: string;
  transaction_id: string;
  customer_id: string;
  created_at: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  triage_decision: "auto_close" | "investigate";
  status: string;
  case_id: string | null;
  reasons: string[];
}

export interface FraudAlert extends FraudAlertSummary {
  account_id: string;
  components: {
    method: string;
    method_explanation: string;
    weighted_average: number;
    breakdown: DetectorContribution[];
    scores: Record<string, number>;
    rules_version: string;
  };
  signals: RiskSignal[];
  rule_hits: RuleHit[];
  ml_explanation: FeatureContribution[] | null;
  model_version: string | null;
}

export interface RecommendedAction {
  action: string;
  label: string;
  rationale: string;
  urgency: "immediate" | "standard";
  requires_analyst_approval: boolean;
}

export interface AppliedAction {
  action: string;
  applied_at: string;
  by: string;
  effect: string | null;
  executed_here: boolean;
}

export interface RankedHypothesis {
  id: string;
  label: string;
  description: string;
  support: number;
  matched: string[];
  missing: string[];
  against: string[];
  unmet_requirements?: string[];
}

export interface GraphNode {
  id: string;
  kind: string;
  ref: string;
  label: string;
  tainted: boolean;
  hops: number;
  focal: boolean;
  in_transaction: boolean;
  x: number;
  y: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string | null;
}

export interface Subgraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

export interface CaseSection {
  agent: string;
  title: string;
  summary: string;
  findings: string[];
  confidence: number;
  data: Record<string, unknown>;
}

export interface CaseFile {
  alert_id: string;
  transaction_id: string;
  customer_id: string;
  generated_at: string;
  model_version: string | null;
  risk: {
    score: number;
    level: RiskLevel;
    method: string;
    method_explanation: string;
    breakdown: DetectorContribution[];
  };
  headline: string | null;
  summary: string | null;
  key_points: string[];
  verification_steps: string[];
  narrative_source: "llm" | "deterministic" | null;
  primary_hypothesis: string | null;
  fraud_type: string | null;
  hypotheses: RankedHypothesis[];
  recommended_actions: RecommendedAction[];
  sections: CaseSection[];
  agents_run: string[];
}

export interface FraudCaseSummary {
  id: string;
  alert_id: string;
  customer_id: string;
  account_id: string;
  transaction_id: string;
  created_at: string | null;
  updated_at: string | null;
  status: CaseStatus;
  priority: "high" | "medium";
  risk_score: number;
  risk_level: RiskLevel;
  primary_hypothesis: string | null;
  fraud_type: string | null;
  summary: string | null;
  assigned_to: string | null;
  decision: CaseDecision | null;
  decided_by: string | null;
  decided_at: string | null;
  alert_ids: string[];
}

export interface CaseNote {
  id: number;
  case_id: string;
  author: string;
  body: string;
  created_at: string | null;
}

export interface FraudCase extends FraudCaseSummary {
  case_file: CaseFile;
  actions: AppliedAction[];
  decision_notes: string | null;
  notes: CaseNote[];
}

export interface FraudDashboard {
  data_available: boolean;
  customers: number;
  transactions: number;
  scored_transactions: number;
  unscored_transactions: number;
  alerts_by_level: Partial<Record<RiskLevel, number>>;
  open_cases: number;
  closed_cases: number;
  cases_by_priority: Record<string, number>;
  cases_by_hypothesis: Record<string, number>;
  amount_at_risk: number;
  active_model: string | null;
  model_metrics: Record<string, number | string | null> | null;
  feedback: {
    total_decisions: number;
    labelled: number;
    inconclusive: number;
    confirmed_fraud: number;
    false_positives: number;
    precision: number | null;
    by_predicted_level: Record<string, { confirmed: number; dismissed: number; precision: number | null }>;
    by_hypothesis: Record<string, { confirmed: number; dismissed: number }>;
  };
  audit_entries: number;
}

export interface ModelVersion {
  id: number;
  version: string;
  created_at: string | null;
  algorithm: string;
  feature_names: string[];
  metrics: Record<string, number | string | null>;
  training_rows: number;
  feedback_rows: number;
  is_active: boolean;
  notes: string | null;
}

export interface ScoreResult {
  scored: number;
  alerts: number;
  cases: number;
  auto_closed: number;
  by_level: Partial<Record<RiskLevel, number>>;
  model_version: string | null;
}

export interface DriftReport {
  available: boolean;
  reason?: string;
  model_version?: string;
  window_days?: number;
  rows_compared?: number;
  max_psi?: number;
  status?: "stable" | "moderate_shift" | "significant_shift";
  shifted_features?: Record<string, number>;
  retrain_recommended?: boolean;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  entity_type: string;
  entity_id: string;
  details: Record<string, unknown> | null;
  hash: string;
  prev_hash: string;
}
