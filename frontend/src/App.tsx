import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { InvoiceListPage } from "./pages/InvoiceListPage";
import { InvoiceDetailPage } from "./pages/InvoiceDetailPage";
import { UploadPage } from "./pages/UploadPage";
import { FraudDashboardPage } from "./pages/FraudDashboardPage";
import { CaseQueuePage } from "./pages/CaseQueuePage";
import { CaseDetailPage } from "./pages/CaseDetailPage";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<InvoiceListPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/invoices/:id" element={<InvoiceDetailPage />} />
        <Route path="/fraud" element={<FraudDashboardPage />} />
        <Route path="/fraud/cases" element={<CaseQueuePage />} />
        <Route path="/fraud/cases/:id" element={<CaseDetailPage />} />
      </Routes>
    </Layout>
  );
}
