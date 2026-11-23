import { Link, useNavigate } from "react-router-dom";
import { useOverview } from "@/shared/api/queries";
import { Card, Empty, ErrorState, HBars, Loading, ReadinessRing, SeverityBar, Sparkline, Stat } from "@/shared/ui";
import { fmtDateTime, fmtNum, plural } from "@/shared/lib/format";
import { quantumLabel } from "@/shared/lib/labels";
import type { QuantumStatus } from "@/shared/api/types";
import { NewScanForm } from "@/features/scans/NewScanForm";

export function OverviewPage() {
  const { data, isLoading, error } = useOverview();
  const navigate = useNavigate();
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;

  if (data.assets.length === 0) {
    return (
      <>
        <div className="page-head">
          <div>
            <h1>Vista general</h1>
            <p>Todavía no hay escaneos.</p>
          </div>
        </div>
        <Card>
          <Empty title="Escaneá tu primer sistema">
            <p>Indicá la carpeta de un repositorio o de configuraciones del servidor. cryptoinv solo lee los archivos: no ejecuta nada.</p>
            <NewScanForm />
          </Empty>
        </Card>
      </>
    );
  }

  const critical = data.by_severity["critica"] ?? 0;
  const high = data.by_severity["alta"] ?? 0;
  const vulnerable = (data.by_quantum_status["vulnerable"] ?? 0) + (data.by_quantum_status["broken"] ?? 0);
  const resistant = data.by_quantum_status["resistant"] ?? 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vista general</h1>
          <p>Estado de cada sistema según su último escaneo. Catálogo de algoritmos {data.catalog_version}.</p>
        </div>
      </div>

      <div className="stack">
        <Card>
          <div className="hero">
            <ReadinessRing value={data.readiness} />
            <div className="hero__text">
              <h2>
                {data.readiness >= 80 ? "Buen punto de partida" : data.readiness >= 40 ? "Migración en curso" : "La migración todavía no empezó"}
              </h2>
              <p>
                El {data.readiness}% de los {fmtNum(data.findings)} usos de criptografía en {plural(data.assets.length, "sistema", "sistemas")} ya no
                depende de algoritmos vulnerables o rotos. NIST desaprueba RSA, curvas elípticas y Diffie-Hellman después de 2030 y los prohíbe
                después de 2035.
              </p>
              <SeverityBar counts={data.by_severity} />
            </div>
          </div>
        </Card>

        <div className="grid grid--stats">
          <Stat label="Críticos" value={fmtNum(critical)} hint="inseguros hoy o fuera de plazo" tone={critical ? "danger" : "ok"} />
          <Stat label="Altos" value={fmtNum(high)} hint="migrar en la primera ola" tone={high ? "warn" : "ok"} />
          <Stat label="Vulnerables o rotos" value={fmtNum(vulnerable)} hint="dependen de algoritmos a reemplazar" />
          <Stat label="Ya resistentes" value={fmtNum(resistant)} hint="ML-KEM, ML-DSA, híbridos" tone="ok" />
          <Stat label="Certificados" value={fmtNum(data.certificates)} />
        </div>

        <Card title="Sistemas" className="card--flush">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Sistema</th>
                  <th className="num">Preparación</th>
                  <th>Evolución</th>
                  <th>Severidad</th>
                  <th className="num">Usos</th>
                  <th>Último escaneo</th>
                </tr>
              </thead>
              <tbody>
                {data.assets.map((a) => (
                  <tr key={a.asset} className="clickable" onClick={() => navigate(`/scans/${a.latest_scan_id}/inventory`)}>
                    <td>
                      <Link className="asset-name" to={`/scans/${a.latest_scan_id}/inventory`} onClick={(e) => e.stopPropagation()}>
                        {a.asset}
                      </Link>
                      <div className="cell-sub">
                        {plural(a.latest.files_scanned, "archivo", "archivos")}
                        {a.latest.in_tests > 0 && ` · ${fmtNum(a.latest.in_tests)} usos en pruebas`}
                      </div>
                    </td>
                    <td className="num">
                      <strong>{a.latest.readiness}%</strong>
                    </td>
                    <td>
                      <Sparkline points={a.trend.map((p) => p.readiness)} />
                    </td>
                    <td>
                      <SeverityBar counts={a.latest.by_severity} compact />
                    </td>
                    <td className="num">{fmtNum(a.latest.findings)}</td>
                    <td className="muted">
                      {fmtDateTime(a.latest_at)}
                      <div className="cell-sub">{plural(a.scans, "escaneo", "escaneos")}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="grid grid--2">
          <Card title="Algoritmos más usados">
            <HBars data={data.by_algorithm} />
          </Card>
          <Card title="Estado frente a la computación cuántica">
            <HBars data={Object.fromEntries(Object.entries(data.by_quantum_status).map(([k, v]) => [quantumLabel[k as QuantumStatus] ?? k, v]))} />
          </Card>
        </div>
      </div>
    </>
  );
}
