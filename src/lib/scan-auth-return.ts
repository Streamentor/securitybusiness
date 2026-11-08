/** Only a scan ID can be carried through OAuth, never an arbitrary redirect URL. */
export function validPendingScanId(value: unknown): string | null {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(value) ? value : null;
}
export function pendingScanFrom(search: string, stored: string | null) {
  return validPendingScanId(new URLSearchParams(search).get("scan")) ?? validPendingScanId(stored);
}
export function safeAuthRedirect(value: string | null) {
  return value && /^\/(?!\/)[A-Za-z0-9/?=&_%#.-]*$/.test(value) ? value : "/dashboard";
}
