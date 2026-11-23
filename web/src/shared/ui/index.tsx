import type { ReactNode } from "react";
import type { QuantumStatus, Severity } from "@/shared/api/types";
import { ApiError } from "@/shared/api/types";
import { SEVERITIES, quantumHelp, quantumLabel, severityLabel } from "@/shared/lib/labels";
import { fmtNum } from "@/shared/lib/format";

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card__head">
          {title && <h2 className="card__title">{title}</h2>}
          {actions && <div className="card__actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "danger" | "ok" | "warn" }) {
  return (
    <div className={`stat ${tone ? "stat--" + tone : ""}`}>
      <div className="stat__label">{label}</div>
      <div className="stat__value">{value}</div>
      {hint && <div className="stat__hint">{hint}</div>}
    </div>
  );
}

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number }) {
  return (
    <span className={`badge badge--sev-${severity}`} title={score !== undefined ? `Puntaje ${score} de 100` : undefined}>
      {severityLabel[severity]}
      {score !== undefined && <span className="badge__score">{score}</span>}
    </span>
  );
}

export function QuantumBadge({ status }: { status: QuantumStatus }) {
  return (
    <span className={`badge badge--q-${status}`} title={quantumHelp[status]}>
      {quantumLabel[status]}
    </span>
  );
}

export function Tag({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="tag" title={title}>
      {children}
    </span>
  );
}

/** Anillo de preparación post-cuántica (0-100). */
export function ReadinessRing({ value, size = 132, label = "preparación" }: { value: number; size?: number; label?: string }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const tone = value >= 80 ? "ok" : value >= 40 ? "warn" : "danger";
  return (
    <figure className={`ring ring--${tone}`} style={{ width: size, height: size }} aria-label={`${value}% de ${label}`}>
      <svg viewBox="0 0 120 120" width={size} height={size} role="img" aria-hidden="true">
        <circle className="ring__track" cx="60" cy="60" r={r} />
        <circle className="ring__bar" cx="60" cy="60" r={r} strokeDasharray={`${(c * value) / 100} ${c}`} transform="rotate(-90 60 60)" />
      </svg>
      <figcaption className="ring__text">
        <strong>{value}%</strong>
        <span>{label}</span>
      </figcaption>
    </figure>
  );
}

/** Barra apilada por severidad, con leyenda. */
export function SeverityBar({ counts, compact = false }: { counts: Record<string, number>; compact?: boolean }) {
  const total = SEVERITIES.reduce((s, k) => s + (counts[k] ?? 0), 0);
  if (total === 0) return <div className="sevbar sevbar--empty">Sin hallazgos</div>;
  return (
    <div className={`sevbar ${compact ? "sevbar--compact" : ""}`}>
      <div className="sevbar__track" role="img" aria-label={SEVERITIES.map((k) => `${severityLabel[k]}: ${counts[k] ?? 0}`).join(", ")}>
        {SEVERITIES.map((k) =>
          counts[k] ? <span key={k} className={`sevbar__seg sev-bg-${k}`} style={{ flexGrow: counts[k] }} title={`${severityLabel[k]}: ${counts[k]}`} /> : null,
        )}
      </div>
      {!compact && (
        <ul className="legend">
          {SEVERITIES.map((k) => (
            <li key={k}>
              <i className={`dot sev-bg-${k}`} />
              {severityLabel[k]} <b>{fmtNum(counts[k] ?? 0)}</b>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Barras horizontales simples (ranking). */
export function HBars({ data, max = 8, onSelect }: { data: Record<string, number>; max?: number; onSelect?: (k: string) => void }) {
  const rows = Object.entries(data)
    .sort((a, b) => b[1] - a[1])
    .slice(0, max);
  const top = rows[0]?.[1] ?? 1;
  return (
    <ul className="hbars">
      {rows.map(([k, v]) => (
        <li key={k}>
          <button type="button" className="hbars__row" onClick={onSelect ? () => onSelect(k) : undefined} disabled={!onSelect}>
            <span className="hbars__label">{k}</span>
            <span className="hbars__bar">
              <i style={{ width: `${(v / top) * 100}%` }} />
            </span>
            <span className="hbars__val">{fmtNum(v)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

/** Línea de evolución de la preparación. */
export function Sparkline({ points, width = 120, height = 32 }: { points: number[]; width?: number; height?: number }) {
  if (points.length < 2) return <span className="muted small">un escaneo</span>;
  const step = width / (points.length - 1);
  const y = (v: number) => height - 2 - (v / 100) * (height - 4);
  const d = points.map((v, i) => `${i ? "L" : "M"}${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const last = points[points.length - 1] ?? 0;
  const first = points[0] ?? 0;
  return (
    <svg className={`spark ${last >= first ? "spark--up" : "spark--down"}`} width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`de ${first}% a ${last}%`}>
      <path d={d} />
      <circle cx={(points.length - 1) * step} cy={y(last)} r="2.5" />
    </svg>
  );
}

export function Loading({ label = "Cargando…" }: { label?: string }) {
  return (
    <div className="state" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const msg = error instanceof ApiError ? (error.status === 404 ? "No existe o fue borrado." : error.message) : "No se pudo conectar con el servidor.";
  return (
    <div className="state state--error" role="alert">
      <strong>Algo salió mal.</strong> {msg}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children}
    </div>
  );
}
