import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { FindingsFilter } from "@/shared/api/types";

export const PAGE_SIZE = 50;

/** Los filtros viven en la URL: se pueden compartir, recargar y volver atrás sin perderlos. */
export function useInventoryParams() {
  const [params, setParams] = useSearchParams();

  const filter = useMemo<FindingsFilter>(() => {
    const list = (k: string) => params.get(k)?.split(",").filter(Boolean) ?? [];
    const page = Math.max(0, Number(params.get("page") ?? 0) || 0);
    const tests = params.get("tests");
    return {
      severity: list("sev"),
      quantum_status: list("qs"),
      algorithm: list("alg"),
      detector: list("det"),
      q: params.get("q") ?? "",
      tests: tests === "exclude" || tests === "only" ? tests : "include",
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    };
  }, [params]);

  const update = (changes: Record<string, string | null>, resetPage = true) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(changes)) {
          if (v === null || v === "") next.delete(k);
          else next.set(k, v);
        }
        if (resetPage) next.delete("page");
        return next;
      },
      { replace: true },
    );

  const toggle = (key: "sev" | "qs" | "alg" | "det", value: string) => {
    const cur = new Set(params.get(key)?.split(",").filter(Boolean) ?? []);
    if (cur.has(value)) cur.delete(value);
    else cur.add(value);
    update({ [key]: [...cur].join(",") || null });
  };

  const selected = params.get("finding");
  const active = ["sev", "qs", "alg", "det", "q", "tests"].some((k) => params.get(k));

  return { filter, update, toggle, selected, active, page: Math.floor((filter.offset ?? 0) / PAGE_SIZE) };
}
