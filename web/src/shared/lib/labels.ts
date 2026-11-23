import type { Primitive, QuantumStatus, Severity } from "@/shared/api/types";

export const SEVERITIES: Severity[] = ["critica", "alta", "media", "baja", "info"];
export const QUANTUM: QuantumStatus[] = ["broken", "vulnerable", "unknown", "weakened", "resistant"];

export const severityLabel: Record<Severity, string> = {
  critica: "Crítica",
  alta: "Alta",
  media: "Media",
  baja: "Baja",
  info: "Info",
};

export const quantumLabel: Record<QuantumStatus, string> = {
  broken: "Inseguro hoy",
  vulnerable: "Vulnerable",
  unknown: "Desconocido",
  weakened: "Aceptable",
  resistant: "Resistente",
};

export const quantumHelp: Record<QuantumStatus, string> = {
  broken: "Ya es inseguro, sin necesidad de una computadora cuántica.",
  vulnerable: "Una computadora cuántica lo rompe (algoritmo de Shor).",
  unknown: "No se pudo identificar el algoritmo.",
  weakened: "La computación cuántica reduce su margen, pero con tamaños adecuados sigue sirviendo.",
  resistant: "Diseñado para resistir computadoras cuánticas.",
};

export const primitiveLabel: Record<Primitive, string> = {
  signature: "Firma",
  "key-agree": "Intercambio de claves",
  pke: "Cifrado asimétrico",
  kem: "Encapsulamiento de claves",
  "block-cipher": "Cifrado por bloques",
  "stream-cipher": "Cifrado de flujo",
  ae: "Cifrado autenticado",
  hash: "Hash",
  mac: "MAC",
  kdf: "Derivación de claves",
  protocol: "Protocolo",
  other: "Otro",
};

export const detectorLabel: Record<string, string> = {
  x509: "Certificados y claves",
  go: "Go",
  python: "Python",
  java: "Java / JVM",
  javascript: "JavaScript / TS",
  ssh: "SSH",
  "tls-config": "Servidores TLS",
  iac: "Infraestructura",
  jwt: "JWT",
};
