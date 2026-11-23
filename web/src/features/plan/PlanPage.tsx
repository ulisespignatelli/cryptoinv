import { Link, useParams } from "react-router-dom";
import { usePlan } from "@/shared/api/queries";
import { Card, Empty, ErrorState, Loading, SeverityBadge, Tag } from "@/shared/ui";
import { fmtNum, location, plural } from "@/shared/lib/format";
import { primitiveLabel } from "@/shared/lib/labels";

const effortLabel = { S: "chico", M: "mediano", L: "grande" } as const;

export function PlanPage() {
  const { id = "" } = useParams();
  const { data, isLoading, error } = usePlan(id);
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;

  const total = data.waves.reduce((s, w) => s + w.items.length, 0);
  if (total === 0) {
    return (
      <Card>
        <Empty title="No hay nada que migrar">
          <p>Todos los usos encontrados ya son resistentes o aceptables ({plural(data.excluded, "uso", "usos")}).</p>
        </Empty>
      </Card>
    );
  }

  return (
    <div className="waves">
      <p className="muted" style={{ margin: 0 }}>
        {plural(total, "tarea", "tareas")} agrupadas por algoritmo y uso, en tres olas. {plural(data.excluded, "uso no requiere", "usos no requieren")} acción. El esfuerzo se estima por la cantidad de archivos.
      </p>
      {data.waves.map((w) =>
        w.items.length === 0 ? null : (
          <section key={w.number} className={`wave--${w.number}`}>
            <div className="wave__head">
              <span className="wave__num">{w.number}</span>
              <h2>{w.title}</h2>
              <span className="wave__deadline">{w.deadline}</span>
            </div>
            <Card className="card--flush">
              {w.items.map((it) => (
                <article key={it.id} className="task">
                  <div>
                    <h3>{it.title}</h3>
                    <p>{it.why}</p>
                    <div className="row" style={{ gap: 6 }}>
                      <Tag>{primitiveLabel[it.primitive]}</Tag>
                      <Tag>{plural(it.findings, "uso", "usos")}</Tag>
                      {it.tests_only && <Tag>solo en pruebas</Tag>}
                    </div>
                    <details style={{ marginTop: 10 }}>
                      <summary>Dónde aparece</summary>
                      <ul>
                        {it.locations.map((l) => (
                          <li key={location(l.path, l.line)} className="path">
                            {location(l.path, l.line)}
                          </li>
                        ))}
                      </ul>
                      {it.findings > it.locations.length && (
                        <Link className="small" to={`../inventory?alg=${it.algorithm_id}`}>
                          Ver los {fmtNum(it.findings)} en el inventario →
                        </Link>
                      )}
                    </details>
                  </div>
                  <div className="task__side">
                    <SeverityBadge severity={it.severity} score={it.max_score} />
                    <span className="effort" title="Esfuerzo estimado por cantidad de archivos">
                      esfuerzo {effortLabel[it.effort]}
                    </span>
                    {it.replacement && (
                      <span className="task__repl">
                        → <b>{it.replacement}</b>
                      </span>
                    )}
                  </div>
                </article>
              ))}
            </Card>
          </section>
        ),
      )}
    </div>
  );
}
