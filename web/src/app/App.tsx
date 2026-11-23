import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./Layout";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { ScansPage } from "@/features/scans/ScansPage";
import { ScanLayout } from "@/features/scans/ScanLayout";
import { InventoryPage } from "@/features/inventory/InventoryPage";
import { PlanPage } from "@/features/plan/PlanPage";
import { CertificatesPage } from "@/features/certificates/CertificatesPage";
import { CatalogPage } from "@/features/catalog/CatalogPage";
import { Empty } from "@/shared/ui";
import { ApiError } from "@/shared/api/types";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
    },
  },
});

// HashRouter: funciona igual embebido en el binario y en GitHub Pages (que no reescribe rutas).
export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="scans" element={<ScansPage />} />
            <Route path="scans/:id" element={<ScanLayout />}>
              <Route index element={<Navigate to="inventory" replace />} />
              <Route path="inventory" element={<InventoryPage />} />
              <Route path="plan" element={<PlanPage />} />
              <Route path="certificates" element={<CertificatesPage />} />
            </Route>
            <Route path="catalog" element={<CatalogPage />} />
            <Route path="*" element={<Empty title="Página inexistente" />} />
          </Route>
        </Routes>
      </HashRouter>
    </QueryClientProvider>
  );
}
