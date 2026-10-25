import Link from "next/link";
import { C } from "@/lib/design/tokens";
import { Panel } from "@/components/design/Panel";

const systems = [
  ["Dark Web Monitoring", "/intelligence/dark-web", "Native onion collection, source coverage, evidence and findings", "DW"],
  ["Detection & Response", "/detection", "Detection posture, incidents, approvals and response playbooks", "DR"],
  ["Web Intelligence", "/intelligence/web", "Targets, pages, search and intelligence collection", "WI"],
  ["Scam Intelligence", "/intelligence/scam", "Message and voice analysis signals", "SC"],
  ["Brand Protection", "/intelligence/brand", "Brand exposure and impersonation monitoring", "BP"],
  ["AI Security", "/convergence/ai", "Canonical AI runs, provider policy and execution evidence", "AI"],
  ["Compliance & Recovery", "/assurance/compliance", "Assurance evidence, recovery readiness and audit", "CR"],
  ["Developer Platform", "/platform/developer", "Applications, credentials and platform integrations", "DP"],
];

const governance = [
  ["Policy & approvals", "Policy gates remain the authority for sensitive operations."],
  ["Identity & access", "Authenticated actor, tenant scope and permission checks."],
  ["Evidence & audit", "Actions must produce attributable, reviewable evidence."],
  ["Emergency controls", "Kill/contain actions stay fail-closed unless their protected backend route is verified."],
];

export default function Kontrol() {
  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="sticky top-0 z-20 flex min-h-16 flex-wrap items-center justify-between gap-3 border-b border-[#1a2330] bg-[#080d13]/95 px-5 backdrop-blur">
        <div>
          <div className="font-semibold tracking-wide">CYCLOTHONE <span className="ml-2 font-mono text-[10px] text-[#00d9ff]">KONTROL</span></div>
          <div className="mt-1 text-[10px] uppercase tracking-[.18em] text-[#647386]">Command Center · Layer 1</div>
        </div>
        <nav className="flex flex-wrap items-center gap-2 text-xs">
          <Link href="/kontrol" className="border border-[#00d9ff]/40 bg-[#00d9ff]/10 px-3 py-2 text-[#8deeff]">Command Center</Link>
          <Link href="/kontrol/engineering" className="border border-[#a8ee62]/40 bg-[#a8ee62]/10 px-3 py-2 text-[#c7ff91]">Engineering AI ↗</Link>
        </nav>
      </header>

      <div className="mx-auto max-w-[1500px] p-5 md:p-8">
        <section className="relative overflow-hidden border border-[#203144] bg-gradient-to-br from-[#0c1a27] via-[#09111a] to-[#071018] p-6 md:p-9">
          <div className="pointer-events-none absolute -right-16 -top-24 h-72 w-72 rounded-full border border-[#00d9ff]/10" />
          <div className="pointer-events-none absolute -right-4 -top-12 h-48 w-48 rounded-full border border-[#00d9ff]/15" />
          <div className="relative max-w-4xl">
            <div className="font-mono text-[10px] uppercase tracking-[.22em] text-[#00d9ff]">Layer 1 · System authority</div>
            <h1 className="mt-3 text-3xl font-semibold md:text-5xl">Kontrol Command Center</h1>
            <p className="mt-4 max-w-3xl text-sm leading-6 text-[#a6b4c5] md:text-base">
              The operational home for Cyclothone. Observe system posture, navigate every security domain, govern execution and inspect evidence. AI can recommend and prepare work; policy and authenticated services retain execution authority.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link href="/kontrol/engineering" className="inline-flex items-center gap-2 border border-[#a8ee62]/50 bg-[#a8ee62]/10 px-4 py-3 text-sm text-[#c7ff91] hover:bg-[#a8ee62]/15">Open Engineering AI <span aria-hidden="true">→</span></Link>
              <Link href="/intelligence/dark-web" className="inline-flex items-center gap-2 border border-[#00d9ff]/40 px-4 py-3 text-sm text-[#8deeff] hover:bg-[#00d9ff]/5">Dark Web Monitoring <span aria-hidden="true">→</span></Link>
            </div>
          </div>
        </section>

        <section className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Command domains">
          {[
            ["01", "System & runtime", "Platform settings, regions and service reachability"],
            ["02", "Security operations", "Detection, investigation and controlled response"],
            ["03", "Intelligence", "Dark Web, web, scam and brand monitoring"],
            ["04", "Trust & governance", "Identity, approvals, compliance and evidence"],
          ].map(([n, title, desc]) => <div key={n} className="border border-[#1a2937] bg-[#0a1119] p-4"><div className="font-mono text-xs text-[#00d9ff]">{n}</div><h2 className="mt-3 text-sm font-medium">{title}</h2><p className="mt-2 text-xs leading-5 text-[#8190a3]">{desc}</p></div>)}
        </section>

        <section className="mt-8">
          <div className="flex flex-wrap items-end justify-between gap-3"><div><div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">System map</div><h2 className="mt-2 text-xl font-semibold">Control every Cyclothone domain</h2></div><span className="text-xs text-[#68788a]">Navigation is not a health claim</span></div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {systems.map(([name, href, description, code]) => <Link key={name} href={href} className="group min-h-36 border border-[#1a2937] bg-[#0a1119] p-4 transition hover:border-[#00d9ff]/50 hover:bg-[#0d1822]"><div className="flex items-start justify-between"><span className="font-mono text-xs text-[#00d9ff]">{code}</span><span className="text-[#53667a] transition group-hover:translate-x-1 group-hover:text-[#00d9ff]">↗</span></div><h3 className="mt-4 text-sm font-medium">{name}</h3><p className="mt-2 text-xs leading-5 text-[#8190a3]">{description}</p></Link>)}
          </div>
        </section>

        <section className="mt-8 grid gap-4 xl:grid-cols-[1.2fr_.8fr]">
          <Panel glow accent={C.kontrolAccent}>
            <div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Layer 1 authority</div>
            <h2 className="mt-2 text-lg font-semibold">System governance</h2>
            <div className="mt-4 space-y-3">{governance.map(([title, desc]) => <div key={title} className="border-b border-[#1a2937] pb-3 last:border-0"><div className="text-sm">{title}</div><p className="mt-1 text-xs leading-5 text-[#8190a3]">{desc}</p></div>)}</div>
            <div className="mt-4 border border-[#ff2d55]/30 bg-[#ff2d55]/5 p-3 text-xs leading-5 text-[#ff8ca0]">No subsystem is marked healthy merely because its page loads. Live status, freshness, source coverage and evidence must come from authenticated runtime responses.</div>
          </Panel>
          <Panel>
            <div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#b8f37d]">Layer 2 · Engineering AI</div>
            <h2 className="mt-2 text-lg font-semibold">A dedicated engineering seat</h2>
            <p className="mt-3 text-sm leading-6 text-[#8190a3]">The engineering chatbot belongs beside this command center—not hidden inside the old navigation. Its workspace is for diagnosing, planning, reviewing and coordinating implementation across GitHub, Vercel, Supabase and Railway.</p>
            <ul className="mt-4 space-y-2 text-xs text-[#a6b4c5]"><li>• Repository, deployment, database and runtime context</li><li>• Evidence-linked diagnosis and implementation plans</li><li>• Explicit approval boundaries for sensitive writes</li><li>• Post-change verification and blocked-state reporting</li></ul>
            <Link href="/kontrol/engineering" className="mt-6 inline-flex border border-[#a8ee62]/40 bg-[#a8ee62]/10 px-4 py-3 text-sm text-[#c7ff91] hover:bg-[#a8ee62]/15">Enter Engineering AI →</Link>
          </Panel>
        </section>

        <footer className="mt-8 border-t border-[#1a2937] pt-4 text-[10px] leading-5 text-[#647386]">Cyclothone Kontrol · Internal control surface. Current system status must be verified from live services; this page deliberately avoids invented health indicators.</footer>
      </div>
    </main>
  );
}
