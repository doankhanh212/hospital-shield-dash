import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/hooks/useTheme";
import DashboardLayout from "./components/layout/DashboardLayout";
import DashboardPage from "./pages/DashboardPage";
import AssetsPage from "./pages/AssetsPage";
import AssetDetailPage from "./pages/AssetDetailPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import NetworkPage from "./pages/NetworkPage";
import AlertsPage from "./pages/AlertsPage";
import XdrPage from "./pages/XdrPage";
import LogsPage from "./pages/LogsPage";
import SettingsPage from "./pages/SettingsPage";
import LoginPage from "./pages/LoginPage";
import AdminUsersPage from "./pages/admin/AdminUsersPage";
import AdminRolesPage from "./pages/admin/AdminRolesPage";
import AdminSystemPage from "./pages/admin/AdminSystemPage";
import AdminRulesPage from "./pages/admin/AdminRulesPage";
import AdminIntegrationsPage from "./pages/admin/AdminIntegrationsPage";
import AdminSetupWizardPage from "./pages/admin/AdminSetupWizardPage";
import AdminDataPage from "./pages/admin/AdminDataPage";
import NotFound from "./pages/NotFound";
import { authStorage } from "./lib/auth";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

/** Redirect to /login if not authenticated. */
const RequireAuth = ({ children }: { children: React.ReactNode }) => {
  if (!authStorage.isLoggedIn()) return <Navigate to="/login" replace />;
  return <>{children}</>;
};

const App = () => (
  <ThemeProvider>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              element={
                <RequireAuth>
                  <DashboardLayout />
                </RequireAuth>
              }
            >
              <Route path="/" element={<DashboardPage />} />
              <Route path="/assets" element={<AssetsPage />} />
              <Route path="/assets/:id" element={<AssetDetailPage />} />
              <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
              <Route path="/network" element={<NetworkPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/xdr"    element={<XdrPage />} />
              <Route path="/logs" element={<LogsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/admin/users" element={<AdminUsersPage />} />
              <Route path="/admin/roles" element={<AdminRolesPage />} />
              <Route path="/admin/system" element={<AdminSystemPage />} />
              <Route path="/admin/rules" element={<AdminRulesPage />} />
              <Route path="/admin/integrations" element={<AdminIntegrationsPage />} />
              <Route path="/admin/setup" element={<AdminSetupWizardPage />} />
              <Route path="/admin/data"  element={<AdminDataPage />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ThemeProvider>
);

export default App;
