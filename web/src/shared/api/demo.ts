import { filterFindings } from "@/shared/lib/filter";
import { ApiError, type Certificate, type DataSource, type FindingsPage } from "./types";

// Modo demostración: lee las respuestas guardadas con `cryptoinv snapshot` (escaneos reales de
// proyectos públicos) y resuelve los filtros en el navegador. Las operaciones que cambian datos no
// están disponibles.

const cache = new Map<string, Promise<unknown>>();

function get<T>(path: string): Promise<T> {
  let p = cache.get(path);
  if (!p) {
    p = fetch(`${import.meta.env.BASE_URL}demo/${path}`).then(async (r) => {
      if (!r.ok) throw new ApiError(r.status, r.status === 404 ? "no encontrado" : r.statusText);
      return r.json();
    });
    p.catch(() => cache.delete(path));
    cache.set(path, p);
  }
  return p as Promise<T>;
}

const safe = (id: string) => {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw new ApiError(404, "no encontrado");
  return id;
};

const readOnly = () => Promise.reject(new ApiError(403, "La demo es de solo lectura: instalá cryptoinv para escanear tus proyectos."));

export const demoSource: DataSource = {
  mode: "demo",
  health: async () => ({ status: "ok", version: "demo", scan_enabled: false, auth_required: false }),
  catalog: () => get("catalog.json"),
  overview: () => get("overview.json"),
  scans: async (asset) => {
    const all = await get<Awaited<ReturnType<DataSource["scans"]>>>("scans.json");
    return asset ? all.filter((s) => s.asset === asset) : all;
  },
  scan: (id) => get(`scans/${safe(id)}.json`),
  findings: async (id, f) => filterFindings((await get<FindingsPage>(`scans/${safe(id)}/findings.json`)).items, f),
  plan: (id) => get(`scans/${safe(id)}/plan.json`),
  certificates: async (id) => {
    const certs = await get<Certificate[]>(`scans/${safe(id)}/certificates.json`);
    const now = Date.now();
    return certs.map((c) => ({ ...c, days_left: Math.floor((Date.parse(c.not_after) - now) / 86_400_000) }));
  },
  createScan: readOnly,
  deleteScan: readOnly,
  exportUrl: () => null,
};
