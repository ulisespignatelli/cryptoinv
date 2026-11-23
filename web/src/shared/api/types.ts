// Tipos de la API. Se derivan del contrato (api/openapi.yaml → schema.gen.ts): si el backend cambia
// el contrato y no se regeneran, la compilación falla.
import type { components } from "./schema.gen";

type S = components["schemas"];
export type Health = S["Health"];
export type Catalog = S["Catalog"];
export type Algorithm = S["Algorithm"];
export type Overview = S["Overview"];
export type AssetStatus = S["AssetStatus"];
export type Summary = S["Summary"];
export type ScanMeta = S["ScanMeta"];
export type ScanDetail = S["ScanDetail"];
export type Finding = S["Finding"];
export type FindingsPage = S["FindingsPage"];
export type MigrationPlan = S["MigrationPlan"];
export type PlanItem = S["PlanItem"];
export type Certificate = S["Certificate"];
export type CreateScanRequest = S["CreateScanRequest"];
export type Severity = S["Severity"];
export type QuantumStatus = S["QuantumStatus"];
export type Primitive = S["Primitive"];
export type ExportFormat = "cbom" | "sarif" | "json";

export interface FindingsFilter {
  severity?: string[];
  quantum_status?: string[];
  algorithm?: string[];
  detector?: string[];
  q?: string;
  tests?: "include" | "exclude" | "only";
  limit?: number;
  offset?: number;
}

/** Fuente de datos del panel: la API real o los JSON estáticos de la demo. */
export interface DataSource {
  readonly mode: "api" | "demo";
  health(): Promise<Health>;
  catalog(): Promise<Catalog>;
  overview(): Promise<Overview>;
  scans(asset?: string): Promise<ScanMeta[]>;
  scan(id: string): Promise<ScanDetail>;
  findings(id: string, filter: FindingsFilter): Promise<FindingsPage>;
  plan(id: string): Promise<MigrationPlan>;
  certificates(id: string): Promise<Certificate[]>;
  createScan(req: CreateScanRequest): Promise<ScanMeta>;
  deleteScan(id: string): Promise<void>;
  /** URL de descarga, o null si la fuente no permite exportar. */
  exportUrl(id: string, format: ExportFormat): string | null;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
