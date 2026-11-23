import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useCreateScan, useHealth } from "@/shared/api/queries";
import { api } from "@/shared/api";

export function NewScanForm({ compact = false }: { compact?: boolean }) {
  const health = useHealth();
  const create = useCreateScan();
  const navigate = useNavigate();
  const [path, setPath] = useState("");
  const [asset, setAsset] = useState("");

  if (api.mode === "demo") {
    return (
      <div className="callout">
        <b>Demo de solo lectura.</b> Instalá cryptoinv y corré <code>cryptoinv serve ./mi-proyecto</code> para escanear tus sistemas.
      </div>
    );
  }
  if (health.data && !health.data.scan_enabled) {
    return <p className="muted">Este servidor se inició con --no-scan: los escaneos se cargan por la API (import) o con la CLI.</p>;
  }

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!path.trim()) return;
    create.mutate({ path: path.trim(), asset: asset.trim() || undefined }, { onSuccess: (m) => navigate(`/scans/${m.id}/inventory`) });
  };

  return (
    <form onSubmit={submit} className={compact ? "row" : "stack"} style={{ maxWidth: compact ? undefined : 560, margin: compact ? undefined : "0 auto", textAlign: "left" }}>
      <div className="field" style={{ flex: 2 }}>
        <label htmlFor="scan-path">Carpeta o archivo</label>
        <input id="scan-path" className="input" placeholder="/home/ulises/proyectos/api  o  C:\proyectos\api" value={path} onChange={(e) => setPath(e.target.value)} />
      </div>
      <div className="field" style={{ flex: 1 }}>
        <label htmlFor="scan-asset">Nombre del sistema (opcional)</label>
        <input id="scan-asset" className="input" placeholder="api-pagos" value={asset} onChange={(e) => setAsset(e.target.value)} />
      </div>
      <div className="row" style={{ alignSelf: compact ? "flex-end" : undefined }}>
        <button className="btn btn--primary" type="submit" disabled={create.isPending || !path.trim()}>
          {create.isPending ? "Escaneando…" : "Escanear"}
        </button>
        {create.isError && <span style={{ color: "var(--sev-critica)" }}>{(create.error as Error).message}</span>}
      </div>
    </form>
  );
}
