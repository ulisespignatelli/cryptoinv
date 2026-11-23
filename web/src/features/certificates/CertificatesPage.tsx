import { useParams } from "react-router-dom";
import { useCertificates } from "@/shared/api/queries";
import { Card, Empty, ErrorState, Loading, SeverityBadge, Tag } from "@/shared/ui";
import { fmtDate, fmtDays, location, shortDN } from "@/shared/lib/format";

export function CertificatesPage() {
  const { id = "" } = useParams();
  const { data, isLoading, error } = useCertificates(id);
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;
  if (data.length === 0) return <Card><Empty title="No se encontraron certificados en este escaneo" /></Card>;

  return (
    <Card className="card--flush">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Certificado</th>
              <th>Clave</th>
              <th>Firma</th>
              <th>Vencimiento</th>
              <th>Riesgo</th>
            </tr>
          </thead>
          <tbody>
            {data.map((c) => {
              const tone = c.days_left < 0 ? "var(--sev-critica)" : c.days_left < 30 ? "var(--sev-alta)" : undefined;
              return (
                <tr key={`${c.path}:${c.line}`}>
                  <td>
                    <div className="cell-main">{shortDN(c.subject)}</div>
                    <div className="cell-sub">{c.self_signed ? "autofirmado" : `emitido por ${shortDN(c.issuer)}`}</div>
                    <div className="path">{location(c.path, c.line)}</div>
                  </td>
                  <td>
                    {c.key_algorithm || "—"}
                    {c.key_bits ? ` ${c.key_bits}` : ""}
                    {c.curve ? ` · ${c.curve}` : ""}
                  </td>
                  <td>
                    <span style={{ color: c.weak_signature_hash ? "var(--sev-critica)" : undefined }}>{c.signature_algorithm}</span>
                  </td>
                  <td>
                    <div style={{ color: tone }}>{fmtDays(c.days_left)}</div>
                    <div className="cell-sub">{fmtDate(c.not_after)}</div>
                  </td>
                  <td>
                    <div className="row" style={{ gap: 6 }}>
                      {c.severity && <SeverityBadge severity={c.severity} score={c.score} />}
                      {c.in_tests && <Tag>prueba</Tag>}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
