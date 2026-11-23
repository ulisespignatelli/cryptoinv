import type { Finding, FindingsFilter, FindingsPage } from "@/shared/api/types";

/**
 * Misma lógica que app.FilterFindings en el backend. La usa el modo demo, que no tiene servidor.
 * Cada faceta se cuenta con los demás filtros aplicados (no con el suyo), para que los números de
 * cada filtro digan cuántos resultados habría al marcarlo.
 */
export function filterFindings(all: Finding[], f: FindingsFilter): FindingsPage {
  const inSet = (v: string, set?: string[]) => !set || set.length === 0 || set.some((s) => s.toLowerCase() === v.toLowerCase());
  const q = (f.q ?? "").trim().toLowerCase();
  const page: FindingsPage = { items: [], total: 0, facets: { severity: {}, quantum_status: {}, algorithm: {}, detector: {} } };
  const inc = (m: Record<string, number>, k: string) => (m[k] = (m[k] ?? 0) + 1);

  for (const x of all) {
    if (f.tests === "exclude" && x.in_tests) continue;
    if (f.tests === "only" && !x.in_tests) continue;
    if (q && !`${x.location.path} ${x.evidence ?? ""} ${x.context ?? ""} ${x.algorithm_name}`.toLowerCase().includes(q)) continue;
    const sev = x.assessment.severity;
    const qs = x.assessment.quantum_status;
    const mSev = inSet(sev, f.severity);
    const mQ = inSet(qs, f.quantum_status);
    const mAlg = inSet(x.algorithm_id, f.algorithm);
    const mDet = inSet(x.detector, f.detector);
    if (mQ && mAlg && mDet) inc(page.facets.severity, sev);
    if (mSev && mAlg && mDet) inc(page.facets.quantum_status, qs);
    if (mSev && mQ && mDet) inc(page.facets.algorithm, x.algorithm_id);
    if (mSev && mQ && mAlg) inc(page.facets.detector, x.detector);
    if (mSev && mQ && mAlg && mDet) {
      page.total++;
      page.items.push(x);
    }
  }
  const offset = f.offset ?? 0;
  const limit = f.limit ?? page.items.length;
  page.items = page.items.slice(offset, offset + limit);
  return page;
}
