import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { allJournalEntriesExportUrl } from "../api";

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>Finance Operations Agent</h1>
        <nav>
          <NavLink to="/" end>
            Invoices
          </NavLink>
          <NavLink to="/dashboard">Dashboard</NavLink>
          <NavLink to="/upload">Upload</NavLink>
          <NavLink to="/fraud">Fraud</NavLink>
          <NavLink to="/fraud/cases">Cases</NavLink>
          <a href={allJournalEntriesExportUrl()}>Export Ledger</a>
        </nav>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}
