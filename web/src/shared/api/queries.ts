import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./index";
import type { CreateScanRequest, FindingsFilter } from "./types";

// Claves de caché en un solo lugar: invalidar después de escanear o borrar es predecible.
export const keys = {
  health: ["health"] as const,
  catalog: ["catalog"] as const,
  overview: ["overview"] as const,
  scans: (asset?: string) => ["scans", asset ?? "*"] as const,
  scan: (id: string) => ["scan", id] as const,
  findings: (id: string, f: FindingsFilter) => ["scan", id, "findings", f] as const,
  plan: (id: string) => ["scan", id, "plan"] as const,
  certificates: (id: string) => ["scan", id, "certificates"] as const,
};

export const useHealth = () => useQuery({ queryKey: keys.health, queryFn: api.health, staleTime: 60_000 });
export const useCatalog = () => useQuery({ queryKey: keys.catalog, queryFn: api.catalog, staleTime: Infinity });
export const useOverview = () => useQuery({ queryKey: keys.overview, queryFn: api.overview });
export const useScans = (asset?: string) => useQuery({ queryKey: keys.scans(asset), queryFn: () => api.scans(asset) });
export const useScan = (id: string) => useQuery({ queryKey: keys.scan(id), queryFn: () => api.scan(id) });
export const useFindings = (id: string, f: FindingsFilter) =>
  useQuery({ queryKey: keys.findings(id, f), queryFn: () => api.findings(id, f), placeholderData: keepPreviousData });
export const usePlan = (id: string) => useQuery({ queryKey: keys.plan(id), queryFn: () => api.plan(id) });
export const useCertificates = (id: string) => useQuery({ queryKey: keys.certificates(id), queryFn: () => api.certificates(id) });

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreateScanRequest) => api.createScan(req),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.overview });
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteScan(id),
    onSuccess: (_d, id) => {
      qc.removeQueries({ queryKey: keys.scan(id) });
      void qc.invalidateQueries({ queryKey: keys.overview });
      void qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}
