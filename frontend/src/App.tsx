import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { SOCLayout } from "./components/layout/SOCLayout";
import { InvestigationsListPage } from "./pages/InvestigationsListPage";
import { InvestigationDetailPage } from "./pages/InvestigationDetailPage";
import { InvestigationReportPage } from "./pages/InvestigationReportPage";
import { SessionDetailPage } from "./pages/SessionDetailPage";

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <SOCLayout>
        <Routes>
          <Route path="/" element={<Navigate to="/investigations" replace />} />
          <Route path="/investigations" element={<InvestigationsListPage />} />
          <Route
            path="/investigations/:id"
            element={<InvestigationDetailPage />}
          />
          <Route
            path="/investigations/:id/report"
            element={<InvestigationReportPage />}
          />
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
          <Route path="*" element={<Navigate to="/investigations" replace />} />
        </Routes>
      </SOCLayout>
    </BrowserRouter>
  );
};

export default App;
