"use client";

import { useEffect, useState } from "react";
import { Check, Copy } from "lucide-react";

async function copyToClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Clipboard access failed");
}

export function CopyPromptButton({ prompt, className = "", label = "Copy fix prompt", copiedLabel = "Prompt copied", ariaLabel = "Copy a technical fix prompt" }: { prompt: string; className?: string; label?: string; copiedLabel?: string; ariaLabel?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => setState("idle"), 2200);
    return () => window.clearTimeout(timer);
  }, [state]);

  async function copyPrompt() {
    try {
      await copyToClipboard(prompt);
      setState("copied");
    } catch {
      setState("error");
    }
  }

  return <button type="button" onClick={copyPrompt} className={`inline-flex min-h-9 items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[0.035] px-3 py-2 text-xs font-semibold text-[#c8d0da] transition hover:border-white/20 hover:bg-white/[0.065] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--signal)]/70 ${className}`} aria-label={ariaLabel}>
    {state === "copied" ? <Check className="h-3.5 w-3.5 text-[var(--signal)]" /> : <Copy className="h-3.5 w-3.5" />}
    {state === "copied" ? copiedLabel : state === "error" ? "Copy failed" : label}
  </button>;
}
