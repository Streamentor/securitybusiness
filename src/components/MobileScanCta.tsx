"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { ArrowUp, Github, Search } from "lucide-react";

const REPO_PATHS = ["/repo-scan", "/guides/github-secret-scanning-for-vibe-coded-apps", "/guides/github-actions-security-for-vibe-coded-apps", "/guides/supabase-security-for-vibe-coded-apps"];

/**
 * Floating scan button for phones. It appears after the visitor scrolls past
 * the hero, hides while a scanner form is on screen, and takes the visitor to
 * the nearest scanner: on the page when there is one, otherwise the scanner page.
 */
export function MobileScanCta() {
  const pathname = usePathname() || "/";
  const router = useRouter();
  const [scrolled, setScrolled] = useState(false);
  const [targetVisible, setTargetVisible] = useState(false);
  const [footerVisible, setFooterVisible] = useState(false);
  const [onPage, setOnPage] = useState(false);

  // Report pages and the app itself have their own actions.
  const hidden = /^\/(repo-scan|scan)\/[^/]+/.test(pathname) || pathname.startsWith("/dashboard") || pathname.startsWith("/admin");
  const repo = REPO_PATHS.includes(pathname);

  useEffect(() => {
    if (hidden) return;
    const onScroll = () => setScrolled(window.scrollY > 520);
    window.addEventListener("scroll", onScroll, { passive: true });

    const visible = new Set<Element>();
    const targetObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) { if (entry.isIntersecting) visible.add(entry.target); else visible.delete(entry.target); }
      setTargetVisible(visible.size > 0);
    }, { threshold: 0.25 });
    const targets = document.querySelectorAll("[data-scan-target]");
    const frame = window.requestAnimationFrame(() => { setOnPage(targets.length > 0); onScroll(); });
    targets.forEach((element) => targetObserver.observe(element));

    const footerObserver = new IntersectionObserver(([entry]) => setFooterVisible(entry.isIntersecting), { threshold: 0.05 });
    const footer = document.querySelector("footer");
    if (footer) footerObserver.observe(footer);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("scroll", onScroll);
      targetObserver.disconnect();
      footerObserver.disconnect();
    };
  }, [hidden, pathname]);

  if (hidden) return null;

  function go() {
    const target = document.querySelector<HTMLElement>("[data-scan-target]");
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      window.setTimeout(() => target.querySelector<HTMLInputElement>("input:not([type=checkbox])")?.focus({ preventScroll: true }), 450);
      return;
    }
    router.push(repo ? "/repo-scan" : "/free-website-vulnerability-scanner#scan");
  }

  const show = scrolled && !targetVisible && !footerVisible;
  const label = repo ? "Scan your GitHub repo" : "Scan your app free";

  return (
    <div aria-hidden={!show} className={`fixed inset-x-0 bottom-0 z-40 px-4 pb-[max(1rem,env(safe-area-inset-bottom))] pt-6 transition-all duration-300 md:hidden ${show ? "pointer-events-auto translate-y-0 opacity-100" : "pointer-events-none translate-y-full opacity-0"} bg-gradient-to-t from-[#06080c] via-[#06080c]/85 to-transparent`}>
      <button type="button" onClick={go} tabIndex={show ? 0 : -1} className="button-primary signal-shadow flex w-full items-center justify-center gap-2 rounded-2xl py-3.5 text-[0.95rem]">
        {repo ? <Github className="h-4 w-4" /> : <Search className="h-4 w-4" />}
        {label}
        {onPage && <ArrowUp className="h-4 w-4 opacity-70" />}
      </button>
      <p className="mt-2 text-center text-[0.68rem] text-[#7f8998]">{repo ? "Read-only · secrets never shown" : "No signup · one free scan per site"}</p>
    </div>
  );
}
