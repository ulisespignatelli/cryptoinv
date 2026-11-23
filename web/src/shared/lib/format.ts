const dateFmt = new Intl.DateTimeFormat("es-AR", { day: "2-digit", month: "short", year: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat("es-AR", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
const numFmt = new Intl.NumberFormat("es-AR");

export const fmtDate = (iso: string) => dateFmt.format(new Date(iso));
export const fmtDateTime = (iso: string) => dateTimeFmt.format(new Date(iso));
export const fmtNum = (n: number) => numFmt.format(n);

export function plural(n: number, one: string, many: string) {
  return `${fmtNum(n)} ${n === 1 ? one : many}`;
}

export function fmtDays(days: number) {
  if (days < 0) return `venció hace ${plural(-days, "día", "días")}`;
  if (days === 0) return "vence hoy";
  if (days > 730) return `vence en ${Math.floor(days / 365)} años`;
  return `vence en ${plural(days, "día", "días")}`;
}

/** Nombre corto de un DN X.509 (el CN, o el DN entero si no tiene). */
export function shortDN(dn: string) {
  const cn = dn.split(",").find((p) => p.trim().startsWith("CN="));
  return cn ? cn.trim().slice(3) : dn || "(sin nombre)";
}

export function location(path: string, line?: number) {
  return line ? `${path}:${line}` : path;
}
