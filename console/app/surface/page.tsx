import { ParticleField } from "@/components/surface/ParticleField";

const CUSTOMER = "https://customers.cyclothone.online";
const DEVELOPERS = "https://developers.cyclothone.online";

export default function Surface() {
  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <nav className="flex h-14 items-center justify-between border-b border-[#1a2330] px-6 md:px-12">
        <a href="/" className="font-semibold tracking-tight">Cyclothone</a>
        <div className="flex items-center gap-4 text-[11px] text-[#8a97a8]">
          <a href="#how">How it works</a>
          <a href="#security">Security</a>
          <a href={DEVELOPERS}>Developer</a>
          <a href={CUSTOMER + "/login"} className="border border-[#2a3646] px-3 py-2">Sign in</a>
        </div>
      </nav>

      <section className="relative overflow-hidden border-b border-[#1a2330] px-6 py-24 md:px-16 md:py-32">
        <ParticleField />
        <div className="relative z-10 max-w-3xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">AI trust infrastructure</div>
          <h1 className="mt-4 text-4xl font-semibold leading-tight md:text-6xl">
            AI can reason.<br />Cyclothone controls execution.
          </h1>
          <p className="mt-6 max-w-2xl text-sm leading-6 text-[#8a97a8]">
            Identity, trust, authorization and evidence stay outside the model so autonomous systems can be governed before they act.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a href={CUSTOMER} className="border border-[#00d9ff] px-5 py-3 text-[11px] text-[#00d9ff]">Customer platform →</a>
            <a href={DEVELOPERS} className="border border-[#2a3646] px-5 py-3 text-[11px]">Developer platform →</a>
          </div>
        </div>
      </section>

      <section id="how" className="border-b border-[#1a2330] px-6 py-16 md:px-16">
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

      <section id="security" className="border-b border-[#1a2330] px-6 py-16 md:px-16">
        <div className="max-w-3xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#00ff9d]">Security boundary</div>
          <h2 className="mt-3 text-3xl font-semibold">Trust stays outside the model.</h2>
          <p className="mt-4 text-sm leading-6 text-[#8a97a8]">
            Signed authority, continuous verification, policy enforcement and durable provenance are independent of model output.
          </p>
        </div>
      </section>

      <section className="px-6 py-16 md:px-16">
        <div className="text-[10px] uppercase tracking-[.18em] text-[#ffb347]">Choose your surface</div>
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <a href={CUSTOMER} className="border border-[#2a3646] bg-[#0a0e14] p-6 hover:border-[#ffb347]">
            <div className="text-[10px] uppercase tracking-[.15em] text-[#ffb347]">Customer</div>
            <h2 className="mt-2 text-xl font-medium">Operate your security services.</h2>
            <p className="mt-2 text-xs leading-5 text-[#8a97a8]">Organization, verification, service requests, cases and customer-visible results.</p>
            <div className="mt-5 text-[11px] text-[#ffb347]">Open customer platform →</div>
          </a>
          <a href={DEVELOPERS} className="border border-[#2a3646] bg-[#0a0e14] p-6 hover:border-[#00ff9d]">
            <div className="text-[10px] uppercase tracking-[.15em] text-[#00ff9d]">Developer</div>
            <h2 className="mt-2 text-xl font-medium">Build against the trust API.</h2>
            <p className="mt-2 text-xs leading-5 text-[#8a97a8]">Authentication, API contracts, playground and integration guidance.</p>
            <div className="mt-5 text-[11px] text-[#00ff9d]">Open developer platform →</div>
          </a>
        </div>
      </section>

      <footer className="border-t border-[#1a2330] px-6 py-6 text-[10px] text-[#5a6675] md:px-16">
        Cyclothone · Public surface
      </footer>
    </main>
  );
}