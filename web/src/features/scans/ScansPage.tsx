import { Link } from "react-router-dom";
import { useDeleteScan, useScans } from "@/shared/api/queries";
import { api } from "@/shared/api";
import { Card, Empty, ErrorState, Loading, SeverityBar } from "@/shared/ui";
import { fmtDateTime, fmtNum } from "@/shared/lib/format";
import { NewScanForm } from "./NewScanForm";

export function ScansPage() {
  const { data, isLoading, error } = useScans();
  const del = useDeleteScan();

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Escaneos</h1>
          <p>Cada escaneo queda guardado: así se ve la evolución de cada sistema y qué cambió entre una corrida y la siguiente.</p>
        </div>
      </div>
      <div className="stack">
        <Card title="Nuevo escaneo">
          <NewScanForm compact />
        </Card>
        <Card title="Historial" className="card--flush">
          {isLoading ? (
            <Loading />
          ) : error || !data ? (
            <ErrorState error={error} />
          ) : data.length === 0 ? (
            <Empty title="Sin escaneos todavía" />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Sistema</th>
                    <th>Fecha</th>
                    <th className="num">Archivos</th>
                    <th className="num">Usos</th>
                    <th className="num">Preparación</th>
                    <th>Severidad</th>
                    {api.mode === "api" && <th />}
                  </tr>
                </thead>
                <tbody>
                  {data.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <Link className="asset-name" to={`/scans/${s.id}/inventory`}>
                          {s.asset}
                        </Link>
                        <div className="cell-sub path" title={s.root}>
                          {s.root}
                        </div>
                      </td>
                      <td className="muted">{fmtDateTime(s.started_at)}</td>
                      <td className="num">{fmtNum(s.summary.files_scanned)}</td>
                      <td className="num">{fmtNum(s.summary.findings)}</td>
                      <td className="num">
                        <strong>{s.summary.readiness}%</strong>
                      </td>
                      <td>
                        <SeverityBar counts={s.summary.by_severity} compact />
                      </td>
                      {api.mode === "api" && (
                        <td className="num">
                          <button
                            type="button"
                            className="btn btn--sm btn--ghost btn--danger"
                            disabled={del.isPending}
                            onClick={() => {
                              if (confirm(`¿Borrar el escaneo de ${s.asset} del ${fmtDateTime(s.started_at)}? No se puede deshacer.`)) del.mutate(s.id);
                            }}
                          >
                            Borrar
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
