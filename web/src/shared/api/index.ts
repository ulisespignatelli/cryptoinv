import { demoSource } from "./demo";
import { httpSource } from "./http";
import type { DataSource } from "./types";

/** La fuente se elige al compilar: `npm run build` (API) o `npm run build:demo` (GitHub Pages). */
export const api: DataSource = import.meta.env.VITE_DATA_SOURCE === "demo" ? demoSource : httpSource;

export * from "./types";
