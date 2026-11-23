import { describe, expect, it } from "vitest";
import { fmtDays, plural, shortDN } from "./format";

describe("format", () => {
  it("pluraliza", () => {
    expect(plural(1, "archivo", "archivos")).toBe("1 archivo");
    expect(plural(1200, "archivo", "archivos")).toBe("1.200 archivos");
  });
  it("describe vencimientos", () => {
    expect(fmtDays(-3)).toBe("venció hace 3 días");
    expect(fmtDays(0)).toBe("vence hoy");
    expect(fmtDays(45)).toBe("vence en 45 días");
    expect(fmtDays(3650)).toBe("vence en 10 años");
  });
  it("acorta DN", () => {
    expect(shortDN("CN=api.ejemplo.test,O=Ejemplo")).toBe("api.ejemplo.test");
    expect(shortDN("O=Sin CN")).toBe("O=Sin CN");
    expect(shortDN("")).toBe("(sin nombre)");
  });
});
