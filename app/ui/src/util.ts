import type { TabInfo } from "./api";

export function hostOf(url: string): string {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname : "";
  } catch {
    return "";
  }
}

export function isBlank(url: string): boolean {
  return !url || url === "about:blank";
}

export function tabTitle(t: TabInfo): string {
  if (t.crashed) return "Page stopped";
  if (t.newTabPage) return "New tab";
  return t.title.trim() || hostOf(t.url) || "New tab";
}

export type Connection = "https" | "http" | "none" | "other";

export function connectionOf(url: string): Connection {
  if (isBlank(url)) return "none";
  if (url.startsWith("https://")) return "https";
  if (url.startsWith("http://")) return "http";
  return "other";
}

export function originOf(url: string): string {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.origin : "";
  } catch {
    return "";
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

/** Seconds since the Unix epoch → local date. */
export function formatDate(secs: number | null): string {
  return secs ? new Date(secs * 1000).toLocaleDateString() : "—";
}