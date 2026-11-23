import { useMemo, useState } from "react";
import { useCatalog } from "@/shared/api/queries";
import { Card, ErrorState, Loading, QuantumBadge } from "@/shared/ui";
import { QUANTUM, primitiveLabel } from "@/shared/lib/labels";

export function CatalogPage() {
  const { data, isLoading, error } = useCatalog();
  const [q, setQ] = useState("");
  const rows = useMemo(() => {
    if (!data) return [];
    const s = q.trim().toLowerCase();
    return [...data.algorithms]
      .filter((a) => !s || [a.name, a.id, a.family, ...(a.aliases ?? [])].some((x) => x.toLowerCase().includes(s)))
      .sort((a, b) => QUANTUM.indexOf(a.quantum) - QUANTUM.indexOf(b.quantum) || a.name.localeCompare(b.name));
  }, [data, q]);

  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Catálogo de algoritmos</h1>
          <p>
            Criterio con el que se evalúa cada uso (versión {data.version}). Es un archivo de datos versionado: cuando cambian las recomendaciones,
            se actualiza sin tocar el código.
          </p>
        </div>
      </div>
      <div className="stack">
        <Card className="card--flush">
          <div className="toolbar">
            <input className="input" type="search" placeholder="Buscar algoritmo o alias (x25519, DESede, HS256…)" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Buscar" />
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Algoritmo</th>
                  <th>Estado</th>
                  <th className="num">Desaprobado</th>
                  <th className="num">Prohibido</th>
                  <th>Reemplazo</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    <td style={{ maxWidth: 420 }}>
                      <div className="cell-main">{a.name}</div>
                      <div className="cell-sub">
                        {primitiveLabel[a.primitive]}
                        {a.min_key_bits ? ` · mínimo ${a.min_key_bits} bits` : ""}
                      </div>
                      <div className="cell-sub" style={{ color: "var(--text-2)" }}>
                        {a.note}
                      </div>
                    </td>
                    <td>
                      <QuantumBadge status={a.quantum} />
                    </td>
                    <td className="num">{a.deprecated_after ?? "—"}</td>
                    <td className="num">{a.disallowed_after ?? "—"}</td>
                    <td style={{ maxWidth: 320 }}>{a.replacement ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Fuentes">
          <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-2)" }}>
            {data.sources.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  );
}
