import { useEffect, useRef } from "react";
import type { Finding } from "@/shared/api/types";
import { useCatalog } from "@/shared/api/queries";
import { QuantumBadge, SeverityBadge, Tag } from "@/shared/ui";
import { detectorLabel, primitiveLabel } from "@/shared/lib/labels";
import { fmtDate, shortDN } from "@/shared/lib/format";

function commentFor(path: string) {
  return /\.(py|rb|sh|conf|cnf|cfg|ya?ml|tf|tfvars|hcl|toml)$|(^|\/)(sshd?_config|authorized_keys)$/i.test(path) ? "#" : "//";
}

export function FindingDrawer({ finding: f, onClose }: { finding: Finding; onClose: () => void }) {
  const catalog = useCatalog();
  const alg = catalog.data?.algorithms.find((a) => a.id === f.algorithm_id);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const a = f.assessment;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="finding-title">
        <div className="row">
          <SeverityBadge severity={a.severity} score={a.score} />
          <QuantumBadge status={a.quantum_status} />
          {f.in_tests && <Tag>prueba</Tag>}
          <span className="spacer" />
          <button ref={closeRef} type="button" className="btn btn--sm btn--ghost" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>
        <h2 id="finding-title" style={{ marginTop: 14 }}>
          {f.algorithm_name}
          {f.key_bits ? ` ${f.key_bits} bits` : ""}
          {f.curve ? ` · ${f.curve}` : ""}
        </h2>
        <p className="path">
          {f.location.path}
          {f.location.line ? `:${f.location.line}` : ""}
        </p>

        {f.evidence && (
          <section>
            <h3>Evidencia</h3>
            <div className="code">{f.evidence}</div>
          </section>
        )}

        <section>
          <h3>Por qué tiene este puntaje</h3>
          <ul className="reasons">
            {a.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </section>

        {a.replacement && (
          <section>
            <h3>Qué usar en su lugar</h3>
            <div className="callout">
              <b>{a.replacement}</b>
            </div>
          </section>
        )}

        {alg?.note && (
          <section>
            <h3>Sobre {alg.name}</h3>
            <p style={{ margin: 0, color: "var(--text-2)" }}>{alg.note}</p>
          </section>
        )}

        {f.certificate && (
          <section>
            <h3>Certificado</h3>
            <dl className="kv">
              <dt>Sujeto</dt>
              <dd>{shortDN(f.certificate.subject)}</dd>
              <dt>Emisor</dt>
              <dd>{f.certificate.self_signed ? "autofirmado" : shortDN(f.certificate.issuer)}</dd>
              <dt>Firma</dt>
              <dd>{f.certificate.signature_algorithm}</dd>
              <dt>Válido hasta</dt>
              <dd>{fmtDate(f.certificate.not_after)}</dd>
            </dl>
          </section>
        )}

        <section>
          <h3>Detalle</h3>
          <dl className="kv">
            <dt>Función</dt>
            <dd>{primitiveLabel[f.primitive]}</dd>
            <dt>Detectado en</dt>
            <dd>
              {detectorLabel[f.detector] ?? f.detector}
              {f.context ? ` · ${f.context}` : ""}
            </dd>
            <dt>Confianza</dt>
            <dd>{f.confidence}</dd>
            {a.deprecated_after ? (
              <>
                <dt>NIST desaprueba</dt>
                <dd>después de {a.deprecated_after}</dd>
              </>
            ) : null}
            {a.disallowed_after ? (
              <>
                <dt>NIST prohíbe</dt>
                <dd>después de {a.disallowed_after}</dd>
              </>
            ) : null}
            <dt>Identificador</dt>
            <dd className="mono">{f.id}</dd>
          </dl>
        </section>

        <section>
          <h3>¿Falso positivo?</h3>
          <p className="small muted" style={{ margin: "0 0 8px" }}>
            Agregá un comentario en esa línea con el motivo y el próximo escaneo lo descarta:
          </p>
          <div className="code">{commentFor(f.location.path)} cryptoinv:ignore motivo</div>
        </section>
      </aside>
    </>
  );
}
