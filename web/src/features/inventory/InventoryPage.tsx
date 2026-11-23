import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useCatalog, useFindings } from "@/shared/api/queries";
import { Card, Empty, ErrorState, Loading, QuantumBadge, SeverityBadge, Tag } from "@/shared/ui";
import { SEVERITIES, QUANTUM, detectorLabel, quantumLabel, severityLabel } from "@/shared/lib/labels";
import { fmtNum, location } from "@/shared/lib/format";
import type { QuantumStatus, Severity } from "@/shared/api/types";
import { PAGE_SIZE, useInventoryParams } from "./useInventoryParams";
import { FindingDrawer } from "./FindingDrawer";

function Facet({ title, options, counts, selected, onToggle }: {
  title: string;
  options: { value: string; label: string }[];
  counts: Record<string, number>;
  selected: string[];
  onToggle: (v: string) => void;
}) {
  return (
    <div className="facet">
      <h3>{title}</h3>
      {options.map((o) => {
        const on = selected.includes(o.value);
        const n = counts[o.value] ?? 0;
        return (
          <button key={o.value} type="button" className="facet__opt" aria-pressed={on} disabled={!on && n === 0} onClick={() => onToggle(o.value)}>
            <span className="check" aria-hidden="true" />
            {o.label}
            <span className="n">{fmtNum(n)}</span>
          </button>
        );
      })}
    </div>
  );
}

export function InventoryPage() {
  const { id = "" } = useParams();
  const { filter, update, toggle, selected, active, page } = useInventoryParams();
  const { data, isLoading, error, isFetching } = useFindings(id, filter);
  const catalog = useCatalog();
  const [search, setSearch] = useState(filter.q ?? "");

  // La búsqueda espera a que se deje de escribir.
  useEffect(() => {
    const t = setTimeout(() => {
      if (search !== (filter.q ?? "")) update({ q: search || null });
    }, 250);
    return () => clearTimeout(t);
  }, [search]); // eslint-disable-line react-hooks/exhaustive-deps

  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;

  const algName = (aid: string) => catalog.data?.algorithms.find((a) => a.id === aid)?.name ?? aid;
  const algOptions = Object.keys({ ...data.facets.algorithm, ...Object.fromEntries((filter.algorithm ?? []).map((a) => [a, 0])) })
    .sort((a, b) => (data.facets.algorithm[b] ?? 0) - (data.facets.algorithm[a] ?? 0))
    .map((a) => ({ value: a, label: algName(a) }));
  const detOptions = Object.keys(data.facets.detector).map((d) => ({ value: d, label: detectorLabel[d] ?? d }));
  const finding = data.items.find((f) => f.id === selected);
  const pages = Math.ceil(data.total / PAGE_SIZE);

  return (
    <div className="inventory">
      <aside className="filters" aria-label="Filtros">
        <Facet title="Severidad" options={SEVERITIES.map((s) => ({ value: s, label: severityLabel[s as Severity] }))} counts={data.facets.severity} selected={filter.severity ?? []} onToggle={(v) => toggle("sev", v)} />
        <Facet title="Estado cuántico" options={QUANTUM.map((q) => ({ value: q, label: quantumLabel[q as QuantumStatus] }))} counts={data.facets.quantum_status} selected={filter.quantum_status ?? []} onToggle={(v) => toggle("qs", v)} />
        <Facet title="Algoritmo" options={algOptions} counts={data.facets.algorithm} selected={filter.algorithm ?? []} onToggle={(v) => toggle("alg", v)} />
        <Facet title="Dónde" options={detOptions} counts={data.facets.detector} selected={filter.detector ?? []} onToggle={(v) => toggle("det", v)} />
      </aside>

      <Card className="card--flush">
        <div className="toolbar">
          <input className="input" type="search" placeholder="Buscar por archivo, código o algoritmo…" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Buscar" />
          <div className="segmented" role="group" aria-label="Código de prueba">
            {(
              [
                ["include", "Todo"],
                ["exclude", "Sin pruebas"],
                ["only", "Solo pruebas"],
              ] as const
            ).map(([v, l]) => (
              <button key={v} type="button" aria-pressed={filter.tests === v} onClick={() => update({ tests: v === "include" ? null : v })}>
                {l}
              </button>
            ))}
          </div>
          {active && (
            <button
              type="button"
              className="btn btn--sm btn--ghost"
              onClick={() => {
                setSearch("");
                update({ sev: null, qs: null, alg: null, det: null, q: null, tests: null });
              }}
            >
              Limpiar filtros
            </button>
          )}
        </div>

        {data.total === 0 ? (
          <Empty title="Nada coincide con los filtros" />
        ) : (
          <div className="table-wrap" style={{ opacity: isFetching ? 0.65 : 1 }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Severidad</th>
                  <th>Algoritmo</th>
                  <th>Ubicación</th>
                  <th className="col-state">Estado</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((f) => (
                  <tr key={f.id} className={`clickable ${f.id === selected ? "selected" : ""}`} onClick={() => update({ finding: f.id }, false)}>
                    <td>
                      <SeverityBadge severity={f.assessment.severity} score={f.assessment.score} />
                    </td>
                    <td className="col-alg">
                      <div className="cell-main">
                        {f.algorithm_name}
                        {f.key_bits ? ` ${f.key_bits}` : ""}
                        {f.curve ? ` · ${f.curve}` : ""}
                      </div>
                      <div className="cell-sub">{f.context}</div>
                    </td>
                    <td>
                      <div className="path">
                        <a
                          href={`#finding-${f.id}`}
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            update({ finding: f.id }, false);
                          }}
                        >
                          {location(f.location.path, f.location.line)}
                        </a>
                      </div>
                      {f.evidence && <div className="evidence" title={f.evidence}>{f.evidence}</div>}
                    </td>
                    <td className="col-state">
                      <div className="row" style={{ gap: 6 }}>
                        <QuantumBadge status={f.assessment.quantum_status} />
                        {f.in_tests && <Tag title="Aparece en tests, fixtures o ejemplos">prueba</Tag>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pager">
          <span>
            {fmtNum(data.total)} {data.total === 1 ? "resultado" : "resultados"}
            {pages > 1 && ` · página ${page + 1} de ${pages}`}
          </span>
          {pages > 1 && (
            <span className="row">
              <button type="button" className="btn btn--sm" disabled={page === 0} onClick={() => update({ page: String(page - 1) }, false)}>
                ← Anterior
              </button>
              <button type="button" className="btn btn--sm" disabled={page + 1 >= pages} onClick={() => update({ page: String(page + 1) }, false)}>
                Siguiente →
              </button>
            </span>
          )}
        </div>
      </Card>

      {finding && <FindingDrawer finding={finding} onClose={() => update({ finding: null }, false)} />}
    </div>
  );
}
