import Link from "next/link";
import { C } from "@/lib/design/tokens";
import { Panel } from "@/components/design/Panel";

const authority = [
  ["Agents", "/kontrol/agents", "AI workload identities"],
  ["Models", "/kontrol/models", "Model registry"],
  ["Providers", "/kontrol/providers", "Provider bindings"],
  ["Missions", "/kontrol/missions", "Hash-bound plans"],
  ["Tools", "/kontrol/tools", "Tool authority"],
  ["Runs", "/kontrol/runs", "Execution records"],
  ["Budgets", "/kontrol/budgets", "Reservations and settlement"],
  ["Audit", "/kontrol/audit", "Authority audit"],
];

const operations = [
  ["Overview", "/detection", "Detection posture and tenant telemetry"],
  ["Detection", "/detection", "Detection results"],
  ["Response", "/response", "Playbooks and controlled response"],
  ["Web Intel", "/intelligence/web", "Web targets, pages and dorks"],
  ["Scam", "/intelligence/scam", "Message intelligence"],
  ["Dark Web", "/intelligence/dark-web", "Watchlists and alerts"],
  ["Brand", "/intelligence/brand", "Brand protection"],
  ["Physical", "/convergence/physical", "Physical/digital correlation"],
  ["Digital Twin", "/convergence/digital-twin", "World-state and simulations"],
  ["AI Security", "/convergence/ai", "AI execution runtime"],
  ["Compliance", "/assurance/compliance", "Compliance assurance"],
  ["Recovery", "/assurance/recovery", "Recovery status"],
  ["Hunting", "/assurance/hunting", "Threat hunting"],
  ["Federation", "/platform/federation", "Threat intelligence exchange"],
  ["Developer", "/platform/developer", "Developer applications"],
  ["Global", "/platform/global", "Regional and channel controls"],
];

export default function Kontrol() {
  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-[#1a2330] bg-[#0a0e14] px-5">
        <div>
          <span className="font-semibold">Cyclothone</span>
          <span className="ml-2 font-mono text-[10px] text-[#ff2d55]">/kontrol</span>
        </div>
        <span className="font-mono text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Internal authority surface</span>
      </header>

      <div className="grid min-h-[calc(100vh-56px)] lg:grid-cols-[240px_1fr]">
        <aside className="border-r border-[#1a2330] bg-[#0a0e14] p-4">
          <div className="mb-3 font-mono text-[9px] uppercase tracking-[.16em] text-[#ff2d55]">Authority</div>
          <nav className="space-y-1" aria-label="Authority navigation">
            {authority.map(([name, href, description]) => (
              <Link key={name} href={href} className="flex items-center justify-between border border-transparent px-3 py-2 text-[11px] text-[#8a97a8] hover:border-[#2a3646] hover:bg-[#111823] hover:text-[#e8eef6]">
                <span>{name}</span><span className="font-mono text-[8px] text-[#5a6675]">{description}</span>
              </Link>
            ))}
          </nav>

          <div className="mb-3 mt-8 font-mono text-[9px] uppercase tracking-[.16em] text-[#00d9ff]">Security operations</div>
          <nav className="space-y-1" aria-label="Security operations navigation">
            {operations.map(([name, href]) => (
              <Link key={name} href={href} className="block border border-transparent px-3 py-2 text-[11px] text-[#8a97a8] hover:border-[#2a3646] hover:bg-[#111823] hover:text-[#e8eef6]">
                {name}
              </Link>
            ))}
          </nav>

          <div className="mt-8 border-t border-[#1a2330] pt-4 text-[9px] leading-4 text-[#5a6675]">
            Internal only. Customer and developer users have separate surfaces. Destructive authority remains fail-closed until its authenticated backend route is available.
          </div>
        </aside>

        <section className="p-5 md:p-8">
          <div className="max-w-4xl">
            <div className="font-mono text-[10px] uppercase tracking-[.16em] text-[#ff2d55]">Authority</div>
            <h1 className="mt-2 text-3xl font-semibold">Control plane</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-[#8a97a8]">
              Internal authority and security-operations surface. AI may reason and plan; this plane remains responsible for policy, approval, execution authority and audit.
            </p>

            <div className="mt-8 grid gap-4 xl:grid-cols-2">
              <Panel>
                <div className="type-h2">AI authority</div>
                <div className="mt-4 space-y-2">
                  {authority.slice(0, 6).map(([name, href, description]) => (
                    <Link key={name} href={href} className="flex items-center justify-between border-b border-[#1a2330] py-2 text-xs">
                      <span>{name}</span><span className="text-[10px] text-[#5a6675]">{description} →</span>
                    </Link>
                  ))}
                </div>
              </Panel>

              <Panel glow accent={C.kontrolAccent}>
                <div className="type-h2">Execution authority</div>
                <p className="mt-2 text-xs leading-5 text-[#8a97a8]">
                  Operational controls are rendered from authenticated backend state. No static armed/live state is claimed.
                </p>
                <div className="mt-5 border border-[#ff2d55]/30 bg-[#ff2d55]/5 p-3 text-[10px] leading-4 text-[#ff6b83]">
                  Kill switches and destructive actions remain unavailable until the corresponding authenticated authority route is verified end-to-end.
                </div>
              </Panel>
            </div>

            <div className="mt-4">
              <Panel>
                <div className="type-h2">Security services</div>
                <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {operations.map(([name, href, description]) => (
                    <Link key={name} href={href} className="border border-[#1a2330] bg-[#0a0e14] p-3 hover:border-[#00d9ff]/50">
                      <div className="text-xs">{name}</div>
                      <div className="mt-1 text-[10px] text-[#5a6675]">{description}</div>
                    </Link>
                  ))}
                </div>
              </Panel>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
