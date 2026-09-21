import { ParticleField } from "@/components/surface/ParticleField";
import { Panel } from "@/components/design/Panel";
import { C } from "@/lib/design/tokens";

const CUSTOMER = "https://customers.cyclothone.online";
const DEVELOPERS = "https://developers.cyclothone.online";

const layers = [
  ["Surface", "cyclothone.online", "Public platform", C.surfaceAccent, "/"],
  ["Customer", "customers.cyclothone.online", "Tenant operations", C.customerAccent, CUSTOMER],
  ["Developer", "developers.cyclothone.online", "APIs and integration", C.developerAccent, DEVELOPERS],
] as const;

const caps = [
  ["Identity", "Versioned, manifest-bound agents. Never an API key."],
  ["Envelope", "Signed execution authority. Model cannot bypass it."],
  ["Mission", "Compiled DAG with hash-bound authority."],
  ["Budget", "Reservation, settlement, release. Never post-hoc."],
  ["Kill switch", "Fail-closed at every node. GLOBAL → TOOL."],
  ["Provenance", "One JSON flight recorder per run."],
] as const;

const security = [
  ["Trust boundary", "Identity, policy, authorization, execution authority, and evidence remain outside the model."],
  ["Cryptographic proof", "Execution artifacts can be bound to signed envelopes, attestations, and provenance."],
  ["Continuous verification", "Trust state can be re-evaluated when measurements or evidence change."],
  ["Fail closed", "Protected execution is denied when required authorization or trust conditions are not satisfied."],
] as const;

export default function Surface() {
  return (
    <main className="min-h-screen bg-[#05070a]">
      <nav className="flex h-14 items-center justify-between border-b border-[#1a2330] px-8">
        <a href="/" className="type-h2">Cyclothone</a>
        <div className="hidden gap-6 md:flex type-code text-[#8a97a8]">
          <a href="#platform">Platform</a>
          <a href="#architecture">Architecture</a>
          <a href="#security">Security</a>
          <a href="#pricing">Access</a>
          <a href={DEVELOPERS}>Docs</a>
          <a href={CUSTOMER + "/login"}>Sign in</a>
        </div>
        <a href={CUSTOMER} className="border border-[#00d9ff] px-4 py-2 type-code text-[#00d9ff]">
          Customer workspace →
        </a>
      </nav>

      <section className="relative flex min-h-[78vh] items-center overflow-hidden border-b border-[#1a2330] px-8 md:px-24">
        <ParticleField />
        <div className="relative z-10 max-w-3xl">
          <div className="type-label">▽ SURFACE LAYER</div>
          <h1 className="type-display mt-4 text-5xl md:text-6xl">
            The invisible infrastructure<br />for autonomous AI.
          </h1>
          <div className="mt-6 h-px w-24 bg-[#00d9ff]" />
          <p className="type-body mt-6 max-w-xl text-[#8a97a8]">
            Signed envelopes. Durable runs. Fail-closed governance. One substrate.
          </p>
          <div className="mt-10 flex flex-wrap gap-3">
            <a href="#architecture" className="border border-[#00d9ff] px-5 py-2.5 type-code text-[#00d9ff]">
              Read the architecture
            </a>
            <a href={CUSTOMER} className="border border-[#2a3646] px-5 py-2.5 type-code">
              Customer workspace →
            </a>
            <a href={DEVELOPERS} className="border border-[#2a3646] px-5 py-2.5 type-code">
              Developer platform →
            </a>
          </div>
        </div>
      </section>

      <section id="architecture" className="px-8 py-16 md:px-24">
        <div className="type-label mb-6">── Platform surfaces ─────────────────</div>
        <div className="grid gap-px bg-[#1a2330] md:grid-cols-3">
          {layers.map(([name, title, description, accent, href]) => (
            <a key={name} href={href} className="bg-[#0a0e14] p-6 transition hover:bg-[#0f1620]">
              <div className="type-label" style={{ color: accent }}>{name}</div>
              <div className="type-h2 mt-3">{title}</div>
              <div className="type-body mt-1 text-[#5a6675]">{description}</div>
              <div className="mt-5 type-code" style={{ color: accent }}>Open surface →</div>
            </a>
          ))}
        </div>
      </section>

      <section id="platform" className="px-8 pb-20 md:px-24">
        <div className="type-label mb-6">── Capabilities ──────────────────</div>
        <div className="grid gap-4 md:grid-cols-3">
          {caps.map(([title, description]) => (
            <Panel key={title} glow>
              <div className="type-h2">{title}</div>
              <div className="type-body mt-2 text-[#8a97a8]">{description}</div>
            </Panel>
          ))}
        </div>
      </section>

      <section id="security" className="border-t border-[#1a2330] px-8 py-20 md:px-24">
        <div className="max-w-3xl">
          <div className="type-label text-[#00ff9d]">── Security ─────────────────────</div>
          <h2 className="type-display mt-3 text-4xl">Trust is outside the model.</h2>
          <p className="type-body mt-5 text-[#8a97a8]">
            Cyclothone separates intelligence from the control and trust boundaries that authorize execution.
          </p>
        </div>
        <div className="mt-10 grid gap-4 md:grid-cols-2">
          {security.map(([title, description]) => (
            <Panel key={title}>
              <div className="type-h2">{title}</div>
              <div className="type-body mt-2 text-[#8a97a8]">{description}</div>
            </Panel>
          ))}
        </div>
      </section>

      <section id="pricing" className="border-t border-[#1a2330] px-8 py-20 md:px-24">
        <div className="type-label text-[#ffb347]">── Access ───────────────────────</div>
        <h2 className="type-display mt-3 text-4xl">Start with the right surface.</h2>
        <p className="type-body mt-5 max-w-2xl text-[#8a97a8]">
          Customer and developer access remain separate. Production access is provisioned according to the service, organization, and trust requirements of the deployment.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a href={CUSTOMER + "/register"} className="border border-[#00d9ff] px-5 py-2.5 type-code text-[#00d9ff]">
            Create customer account
          </a>
          <a href={CUSTOMER + "/request-service"} className="border border-[#2a3646] px-5 py-2.5 type-code">
            Request a service
          </a>
          <a href={DEVELOPERS} className="border border-[#2a3646] px-5 py-2.5 type-code">
            Developer access
          </a>
        </div>
      </section>

      <footer className="border-t border-[#1a2330] px-8 py-8 md:px-24">
        <div className="flex flex-wrap gap-6 type-code text-[#5a6675]">
          <a href={CUSTOMER}>Customer workspace</a>
          <a href={DEVELOPERS}>Developer platform</a>
          <a href={CUSTOMER + "/login"}>Sign in</a>
        </div>
      </footer>
    </main>
  );
}
