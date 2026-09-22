import type { ApprovalStatus } from "../types";

const LABELS: Record<ApprovalStatus, string> = {
  pending: "Pending Review",
  auto_approved: "Auto-Approved",
  approved: "Approved",
  rejected: "Rejected",
};

export function StatusBadge({ status }: { status: ApprovalStatus }) {
  return <span className={`badge badge-${status}`}>{LABELS[status]}</span>;
}
