import { describe, expect, it } from "vitest";
import type { Finding } from "@/shared/api/types";
import { filterFindings } from "./filter";

const f = (id: string, alg: string, sev: Finding["assessment"]["severity"], qs: Finding["assessment"]["quantum_status"], path: string, inTests = false): Finding => ({
  id,
  algorithm_id: alg,
  algorithm_name: alg.toUpperCase(),
  primitive: "signature",
  location: { path, line: 1 },
  asset: "a",
  detector: "go",
  confidence: "alta",
  in_tests: inTests,
  assessment: { score: 50, severity: sev, quantum_status: qs, reasons: [] },
});

const all = [
  f("1", "rsa", "critica", "vulnerable", "cmd/main.go"),
  f("2", "rsa", "media", "vulnerable", "pkg/a.go"),
  f("3", "md5", "alta", "broken", "pkg/b.go"),
  f("4", "mlkem", "info", "resistant", "pkg/c.go"),
  f("5", "sha1", "alta", "broken", "test/x_test.go", true),
];

describe("filterFindings (paridad con app.FilterFindings)", () => {
  it("sin filtros devuelve todo", () => {
    const p = filterFindings(all, {});
    expect(p.total).toBe(5);
    expect(p.facets.severity).toEqual({ critica: 1, media: 1, alta: 2, info: 1 });
  });
  it("las facetas no se achican por su propio filtro", () => {
    const p = filterFindings(all, { severity: ["alta"] });
    expect(p.total).toBe(2);
    expect(p.facets.severity.critica).toBe(1);
    expect(p.facets.algorithm).toEqual({ md5: 1, sha1: 1 });
  });
  it("combina filtros, búsqueda y pruebas", () => {
    expect(filterFindings(all, { algorithm: ["rsa"], severity: ["critica", "media"] }).total).toBe(2);
    expect(filterFindings(all, { q: "PKG/" }).total).toBe(3);
    expect(filterFindings(all, { tests: "exclude" }).total).toBe(4);
    expect(filterFindings(all, { tests: "only" }).items.map((x) => x.id)).toEqual(["5"]);
  });
  it("pagina después de contar", () => {
    const p = filterFindings(all, { limit: 2, offset: 1 });
    expect(p.total).toBe(5);
    expect(p.items.map((x) => x.id)).toEqual(["2", "3"]);
  });
});
