"use client";
import { useEffect, useState } from "react";
export function EmailUpdates() {
  const [pref, setPref] = useState<{ enabled: boolean; suppressed: boolean } | null>(null);
  const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { let active = true; fetch("/api/email/preferences").then(r => { if (!r.ok) throw new Error(); return r.json(); }).then(p => { if (active) setPref(p); }).catch(() => { if (active) setMessage("Email preferences unavailable. Reload to retry."); }); return () => { active = false; }; }, []);
  async function update() {
    if (!pref) return; setBusy(true); setMessage("");
    try { const r = await fetch("/api/email/preferences", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: !pref.enabled }) }); if (!r.ok) throw new Error(); setPref(await r.json()); setMessage("Preference saved."); }
    catch { setMessage("Could not save. Please try again."); } finally { setBusy(false); }
  }
  return <section className="surface mt-6 rounded-2xl p-5" aria-labelledby="email-updates-title"><h2 id="email-updates-title" className="font-semibold">Email updates</h2><p className="mt-1 text-sm text-[#98a2b3]">Personal notes about your scans and ScanMySaaS. Unsubscribe anytime. Existing accounts are not automatically enrolled.</p><button type="button" role="switch" aria-checked={pref?.enabled || false} disabled={!pref || busy || pref.suppressed} onClick={update} className="button-secondary mt-3">{busy ? "Saving..." : !pref ? "Loading preference..." : pref.suppressed ? "Sending paused for this address" : pref.enabled ? "Email updates on" : "Email updates off"}</button><p role="status" className="mt-2 text-xs text-[#98a2b3]">{message}</p></section>;
}
