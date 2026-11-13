import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ScanProvider } from "@/context/ScanContext";
import { DashboardPage } from "@/pages/DashboardPage";
import { ScansPage } from "@/pages/ScansPage";
import { ScanDetailPage } from "@/pages/ScanDetailPage";
import { DependenciesPage } from "@/pages/DependenciesPage";
import { ComparePage } from "@/pages/ComparePage";
import { SettingsPage } from "@/pages/SettingsPage";

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <ScanProvider>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<DashboardPage />} />
              <Route path="scans" element={<ScansPage />} />
              <Route path="scans/:scanId" element={<ScanDetailPage />} />
              <Route path="dependencies" element={<DependenciesPage />} />
              <Route path="compare" element={<ComparePage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </ScanProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
