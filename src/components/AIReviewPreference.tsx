"use client";
import { useEffect, useState } from "react";

export function AIReviewPreference() {
  const [settings, setSettings] = useState<{eligible: boolean; enabled: boolean} | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => { let active = true; fetch("/api/repo-scans/preferences", {cache: "no-store"}).then((r) => r.ok ? r.json() : null).then((data) => {if (active) setSettings(data);}).catch(() => {}); return () => {active = false;}; }, []);
  if (!settings?.eligible) return null;
  async function change(enabled: boolean) {
    setSaving(true); setMessage("");
    try {
      const response = await fetch("/api/repo-scans/preferences", {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({enabled})});
      if (!response.ok) throw new Error("save failed");
      setSettings({eligible: true, enabled}); setMessage(enabled ? "AI review enabled for future scans." : "AI review disabled for future scans.");
    } catch {setMessage("Could not save. Your previous setting is unchanged.");}
    finally {setSaving(false);}
  }
  return <div className="my-4 rounded-xl border border-white/10 bg-white/[0.025] p-4 text-sm">
    <label className="flex items-start gap-3"><input type="checkbox" className="mt-1" checked={settings.enabled} disabled={saving} onChange={(e) => change(e.target.checked)} /><span><strong className="text-white">AI logic review</strong><span className="mt-1 block text-xs leading-5 text-[#9ba5b3]">For paid-plan repository scans, selected source files are sent to OpenAI for analysis with storage disabled (store: false). Findings need verification. Monthly limits apply. Turn this off to keep future scans rule-based.</span></span></label>
    <p role="status" className="mt-2 text-xs text-[#9ba5b3]">{message}</p>
  </div>;
}
