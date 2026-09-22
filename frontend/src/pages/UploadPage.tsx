import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { uploadInvoice } from "../api";

export function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!file) return;
    setStatus("uploading");
    setError(null);
    try {
      const invoice = await uploadInvoice(file);
      navigate(`/invoices/${invoice.id}`);
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "Upload failed");
    }
  }

  return (
    <section className="card">
      <h2>Upload Invoice</h2>
      <p className="muted">
        Accepted formats: PDF, PNG, JPEG. The invoice runs through OCR extraction, validation,
        duplicate detection, fraud checks, and approval routing automatically.
      </p>
      <form onSubmit={handleSubmit}>
        <input
          type="file"
          accept="application/pdf,image/png,image/jpeg,image/webp"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        <button type="submit" disabled={!file || status === "uploading"}>
          {status === "uploading" ? "Processing..." : "Upload & Process"}
        </button>
      </form>
      {error && <p className="error">{error}</p>}
    </section>
  );
}
