import { Link, NavLink, Outlet, useNavigate, useParams } from "react-router-dom";
import { useScan, useScans } from "@/shared/api/queries";
import { api, type ExportFormat } from "@/shared/api";
import { ErrorState, Loading, ReadinessRing, SeverityBar } from "@/shared/ui";
import { fmtDateTime, fmtNum, plural } from "@/shared/lib/format";

const exports: { format: ExportFormat; label: string; title: string }[] = [
  { format: "cbom", label: "CBOM", title: "CycloneDX 1.6: inventario criptográfico estándar" },
  { format: "sarif", label: "SARIF", title: "SARIF 2.1.0: para GitHub code scanning y otras plataformas" },
  { format: "json", label: "JSON", title: "Formato nativo de cryptoinv" },
];

export function ScanLayout() {
  const { id = "" } = useParams();
  const scan = useScan(id);
  const history = useScans(scan.data?.asset);
  const navigate = useNavigate();

  if (scan.isLoading) return <Loading />;
  if (scan.error || !scan.data) return <ErrorState error={scan.error} />;
  const s = scan.data;
  const sum = s.summary;

  return (
    <>
      <div className="crumbs">
        <Link to="/">Vista general</Link> / {s.asset}
      </div>
      <div className="page-head">
        <div className="row" style={{ gap: 20, alignItems: "center" }}>
          <ReadinessRing value={sum.readiness} size={92} />
          <div>
            <h1>{s.asset}</h1>
            <p className="path" title={s.root}>
              {s.root}
            </p>
            <p className="small">
              {fmtDateTime(s.started_at)} · {plural(sum.files_scanned, "archivo", "archivos")} · {plural(sum.findings, "uso", "usos")}
              {s.previous_scan_id && (
                <>
                  {" · "}
                  <span style={{ color: s.new_findings ? "var(--sev-alta)" : undefined }}>+{fmtNum(s.new_findings)} nuevos</span>
                  {" · "}
                  <span style={{ color: s.resolved_findings ? "var(--q-resistant)" : undefined }}>−{fmtNum(s.resolved_findings)} resueltos</span>
                  <span className="muted"> desde el escaneo anterior</span>
                </>
              )}
            </p>
          </div>
        </div>
        <div className="stack" style={{ gap: 10, alignItems: "flex-end" }}>
          {history.data && history.data.length > 1 && (
            <select className="input" aria-label="Escaneo" value={id} onChange={(e) => navigate(`/scans/${e.target.value}/inventory`)}>
              {history.data.map((h) => (
                <option key={h.id} value={h.id}>
                  {fmtDateTime(h.started_at)} · {h.summary.readiness}%
                </option>
              ))}
            </select>
          )}
          <div className="row">
            {exports.map((e) => {
              const url = api.exportUrl(id, e.format);
              return url ? (
                <a key={e.format} className="btn btn--sm" href={url} title={e.title} download>
                  ↓ {e.label}
                </a>
              ) : (
                <button key={e.format} type="button" className="btn btn--sm" disabled title="No disponible en la demo">
                  ↓ {e.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>
      <div style={{ marginBottom: 18 }}>
        <SeverityBar counts={sum.by_severity} />
      </div>
      <nav className="tabs" aria-label="Secciones del escaneo">
        <NavLink to="inventory">
          Inventario<span className="count">{fmtNum(sum.findings)}</span>
        </NavLink>
        <NavLink to="plan">Plan de migración</NavLink>
        <NavLink to="certificates">
          Certificados<span className="count">{fmtNum(sum.certificates)}</span>
        </NavLink>
      </nav>
      <Outlet />
    </>
  );
}
