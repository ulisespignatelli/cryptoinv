import { ApiError, type DataSource, type FindingsFilter } from "./types";

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: {
      Accept: "application/json",
      // Defensa contra CSRF: el servidor rechaza cambios sin este encabezado.
      "X-Requested-With": "cryptoinv",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as { error?: string }).error ?? msg;
    } catch {
      /* respuesta sin JSON */
    }
    throw new ApiError(res.status, msg);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export function findingsQuery(f: FindingsFilter): string {
  const p = new URLSearchParams();
  const list = (k: string, v?: string[]) => v && v.length > 0 && p.set(k, v.join(","));
  list("severity", f.severity);
  list("quantum_status", f.quantum_status);
  list("algorithm", f.algorithm);
  list("detector", f.detector);
  if (f.q) p.set("q", f.q);
  if (f.tests && f.tests !== "include") p.set("tests", f.tests);
  if (f.limit) p.set("limit", String(f.limit));
  if (f.offset) p.set("offset", String(f.offset));
  const s = p.toString();
  return s ? "?" + s : "";
}

const enc = encodeURIComponent;

export const httpSource: DataSource = {
  mode: "api",
  health: () => request("/health"),
  catalog: () => request("/catalog"),
  overview: () => request("/overview"),
  scans: (asset) => request("/scans" + (asset ? "?asset=" + enc(asset) : "")),
  scan: (id) => request(`/scans/${enc(id)}`),
  findings: (id, f) => request(`/scans/${enc(id)}/findings${findingsQuery(f)}`),
  plan: (id) => request(`/scans/${enc(id)}/plan`),
  certificates: (id) => request(`/scans/${enc(id)}/certificates`),
  createScan: (req) => request("/scans", { method: "POST", body: JSON.stringify(req) }),
  deleteScan: (id) => request(`/scans/${enc(id)}`, { method: "DELETE" }),
  exportUrl: (id, format) => `${BASE}/scans/${enc(id)}/export?format=${format}`,
};
