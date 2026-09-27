import { ParticleField } from "@/components/surface/ParticleField";

const CUSTOMER = "https://customers.cyclothone.online";
const DEVELOPERS = "https://developers.cyclothone.online";

const planes = [
  ["Identity & World", "Identity, admission, devices, data and world state."],
  ["Security Operations", "Security intelligence, detection, hunting, investigation and cases."],
  ["Trust & Control", "Risk, policy, trust, authorization and controlled response."],
  ["Intelligence & AI", "AI control, intelligence, trust and governed autonomy."],
  ["Execution & Orchestration", "Response, recovery, orchestration and governance."],
];

export default function Surface() {
  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <nav className="flex min-h-14 items-center justify-between border-b border-[#1a2330] px-5 md:px-12">
        <a href="/" className="font-semibold tracking-tight">Cyclothone</a>
        <div className="flex items-center gap-4 text-[10px] text-[#8a97a8]">
          <a href="/platform">Platform</a>
          <a href="#how">How it works</a>
          <a href="#security">Security</a>
          <a href={DEVELOPERS}>Developer</a>
          <a href={CUSTOMER + "/login"} className="border border-[#2a3646] px-3 py-2">Sign in</a>
        </div>
      </nav>

      <section className="relative overflow-hidden border-b border-[#1a2330] px-5 py-20 md:px-16 md:py-28">
        <ParticleField />
        <div className="relative z-10 max-w-4xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Zero-trust security operations</div>
          <h1 className="mt-4 text-4xl font-semibold leading-tight md:text-6xl">
            See the whole system.<br />Then enter the protected platform.
          </h1>
          <p className="mt-6 max-w-3xl text-sm leading-6 text-[#8a97a8]">
            Cyclothone connects identity, security operations, trust and control, intelligence and AI, and execution into one governed security platform. Explore the architecture and capabilities first. Authentication begins only when you enter a protected destination or request an authorized operation.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a href="/platform" className="border border-[#00d9ff] px-5 py-3 text-[11px] text-[#00d9ff]">Explore the full platform →</a>
            <a href={CUSTOMER + "/login"} className="border border-[#2a3646] px-5 py-3 text-[11px]">Customer sign in →</a>
            <a href={DEVELOPERS} className="border border-[#2a3646] px-5 py-3 text-[11px]">Developer platform →</a>
          </div>
        </div>
      </section>

      <section className="border-b border-[#1a2330] px-5 py-14 md:px-16 md:py-16">
        <div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">Five planes · fifteen layers</div>
        <div className="mt-5 grid gap-px bg-[#1a2330] md:grid-cols-5">
          {planes.map(([name, description], i) => (
            <a key={name} href={"/platform#layer-" + String(i + 1).padStart(2, "0")} className="bg-[#0a0e14] p-5 hover:bg-[#0d121a]">
              <div className="font-mono text-[10px] text-[#00d9ff]">0{i + 1}</div>
              <h2 className="mt-3 text-sm font-medium">{name}</h2>
              <p className="mt-2 text-[10px] leading-4 text-[#8a97a8]">{description}</p>
            </a>
          ))}
        </div>
        <a href="/platform" className="mt-5 inline-block text-[10px] text-[#00d9ff]">Open the complete 15-layer map →</a>
      </section>

      <section id="how" className="border-b border-[#1a2330] px-5 py-14 md:px-16 md:py-16">
        <div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">How it works</div>
        <div className="mt-6 grid gap-px bg-[#1a2330] md:grid-cols-3">
          {[
            ["1", "AI reasons", "Models and agents produce plans or requests."],
            ["2", "Trust verifies", "Identity, policy, evidence and authority are checked."],
            ["3", "Execution acts", "Only authorized actions are dispatched and recorded."],
          ].map(([n,t,d]) => (
            <div key={n} className="bg-[#0a0e14] p-6">
              <div className="font-mono text-[#00d9ff]">{n}</div>
              <h2 className="mt-3 text-lg font-medium">{t}</h2>
              <p className="mt-2 text-xs leading-5 text-[#8a97a8]">{d}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="security" className="border-b border-[#1a2330] px-5 py-14 md:px-16 md:py-16">
        <div className="max-w-3xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#00ff9d]">Security boundary</div>
          <h2 className="mt-3 text-3xl font-semibold">Trust stays outside the model.</h2>
          <p className="mt-4 text-sm leading-6 text-[#8a97a8]">
            Signed authority, continuous verification, policy enforcement and durable provenance remain independent of model output.
          </p>
        </div>
      </section>

      <section className="px-5 py-14 md:px-16 md:py-16">
        <div className="text-[10px] uppercase tracking-[.18em] text-[#ffb347]">Enter when you are ready</div>
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <a href={CUSTOMER + "/login"} className="border border-[#2a3646] bg-[#0a0e14] p-6 hover:border-[#ffb347]">
            <div className="text-[10px] uppercase tracking-[.15em] text-[#ffb347]">Customer</div>
            <h2 className="mt-2 text-xl font-medium">Operate protected security services.</h2>
            <p className="mt-2 text-xs leading-5 text-[#8a97a8]">Organization, verification, admission, service requests, cases and customer-visible results.</p>
            <div className="mt-5 text-[11px] text-[#ffb347]">Sign in / create account →</div>
          </a>
          <a href={DEVELOPERS} className="border border-[#2a3646] bg-[#0a0e14] p-6 hover:border-[#00ff9d]">
            <div className="text-[10px] uppercase tracking-[.15em] text-[#00ff9d]">Developer</div>
            <h2 className="mt-2 text-xl font-medium">Build against the trust API.</h2>
            <p className="mt-2 text-xs leading-5 text-[#8a97a8]">Authentication, applications, credentials, OAuth, documentation and integration guidance.</p>
            <div className="mt-5 text-[11px] text-[#00ff9d]">Open developer platform →</div>
          </a>
        </div>
      </section>

      <footer className="border-t border-[#1a2330] px-5 py-6 text-[10px] text-[#5a6675] md:px-16">
        Cyclothone · Public front door · Protected operations require real identity and authorization.
      </footer>
    </main>
  );
}
