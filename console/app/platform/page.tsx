import Link from "next/link";

type Service = { key: string; name: string; description: string };
type Layer = { id: string; name: string; description: string; services: Service[] };

const planes: { name: string; description: string; layers: Layer[] }[] = [
  {
    name: "Identity & World",
    description: "Establish who is acting, what exists, and which organization or world state the action belongs to.",
    layers: [
      { id: "01", name: "Global Identity", description: "Identity, account and principal foundations used across Cyclothone.", services: [] },
      { id: "02", name: "Customer & Admission", description: "Organization onboarding, verification, admission and tenant establishment.", services: [{ key: "cybersecurity_assessment", name: "Customer onboarding", description: "Organization, verification and admission before protected operations." }] },
      { id: "03", name: "Device & Infrastructure Identity", description: "Identity and trust context for devices, infrastructure and connected security assets.", services: [{ key: "soc_mdr", name: "SOC / MDR", description: "Managed security operations around authorized infrastructure." }] },
    ],
  },
  {
    name: "Security Operations",
    description: "Observe, detect, investigate and manage security-relevant activity using authorized evidence.",
    layers: [
      { id: "04", name: "Data & Evidence", description: "Evidence, provenance and customer-visible records that support security decisions.", services: [{ key: "compliance", name: "Compliance", description: "Evidence and assurance results for approved frameworks." }] },
      { id: "05", name: "Security Intelligence", description: "Threat, exposure and intelligence capabilities across approved sources.", services: [
        { key: "threat_intelligence", name: "Threat Intelligence", description: "Relevant indicators and threat information." },
        { key: "web_intelligence", name: "Web Intelligence", description: "Approved web targets and security-relevant findings." },
        { key: "dark_web_monitoring", name: "Dark Web Monitoring", description: "Approved-source exposure monitoring." },
        { key: "brand_protection", name: "Brand Protection", description: "Brand abuse and impersonation monitoring." },
        { key: "scam_monitoring", name: "Scam Monitoring", description: "Approved scam-related exposure monitoring." },
        { key: "mobile_digital_intelligence", name: "Mobile & Digital Intelligence", description: "Authorized mobile, device, network and location intelligence." },
      ] },
      { id: "06", name: "Investigation & Cases", description: "Turn authorized findings into investigations, cases and documented outcomes.", services: [
        { key: "investigation", name: "Investigation", description: "Evidence-backed authorized investigations." },
        { key: "hunting", name: "Threat Hunting", description: "Approved hunts against authorized scope." },
        { key: "incident_response", name: "Incident Response", description: "Coordinated response to active or suspected incidents." },
      ] },
    ],
  },
  {
    name: "Trust & Control",
    description: "Keep authority, policy, risk and trust decisions outside the model and enforce them before action.",
    layers: [
      { id: "07", name: "Response & Execution", description: "Controlled transition from an authorized decision to an executable action.", services: [{ key: "incident_response", name: "Incident Response", description: "Controlled response activity and documented outcomes." }] },
      { id: "08", name: "Policy & Risk Control", description: "Risk, policy and compliance controls that constrain protected operations.", services: [{ key: "compliance", name: "Compliance", description: "Framework assessment and assurance evidence." }, { key: "cybersecurity_assessment", name: "Cybersecurity Assessment", description: "Security posture and verified gaps." }] },
      { id: "09", name: "Trust Infrastructure", description: "Verification, attestation, authorization and continuous trust boundaries.", services: [{ key: "ai_security", name: "AI Security", description: "Security controls around AI systems and exposure." }] },
    ],
  },
  {
    name: "Intelligence & AI",
    description: "Models, agents and investigation intelligence operate within explicit trust and authorization boundaries.",
    layers: [
      { id: "10", name: "Digital Twin & World State", description: "Represent authorized assets, physical context and changing world state.", services: [{ key: "physical_security", name: "Physical Security", description: "Approved physical security assets and events." }] },
      { id: "11", name: "Federation & Trust Exchange", description: "Controlled exchange of trust and intelligence signals across authorized boundaries.", services: [] },
      { id: "12", name: "AI Control Plane", description: "AI providers, models, agents, missions, tools and lifecycle controls.", services: [{ key: "ai_security", name: "AI Security", description: "AI-system security and operational controls." }] },
    ],
  },
  {
    name: "Execution & Orchestration",
    description: "Coordinate response, recovery, automation and governance while preserving evidence of what happened.",
    layers: [
      { id: "13", name: "AI Trust & Autonomy", description: "Bound autonomous intelligence with trust, admission and authorization controls.", services: [{ key: "mobile_digital_intelligence", name: "Investigation Copilot", description: "Evidence-backed assistance; it does not authorize or execute actions." }] },
      { id: "14", name: "Global Orchestration", description: "Coordinate security workflows across services, cases and execution paths.", services: [{ key: "soc_mdr", name: "SOC / MDR", description: "Security operations monitoring and managed workflows." }, { key: "recovery", name: "Recovery", description: "Approved recovery workflow and documented result." }] },
      { id: "15", name: "Governance, Audit & Public Trust", description: "Governance, auditability, assurance and durable public trust around platform operation.", services: [{ key: "compliance", name: "Compliance", description: "Assurance status, evidence and compliance results." }] },
    ],
  },
];

const serviceNames = new Set(planes.flatMap(p => p.layers.flatMap(l => l.services.map(s => s.key))));

export default function Platform() {
  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <nav className="sticky top-0 z-20 flex min-h-14 items-center justify-between border-b border-[#1a2330] bg-[#05070a]/95 px-5 backdrop-blur md:px-12">
        <Link href="/" className="font-semibold tracking-tight">Cyclothone</Link>
        <div className="flex items-center gap-3 text-[10px] text-[#8a97a8]">
          <a href="#planes">Platform</a>
          <a href="#flow">How it works</a>
          <a href="https://developers.cyclothone.online">Developer</a>
          <a href="https://customers.cyclothone.online/login" className="border border-[#2a3646] px-3 py-2">Sign in</a>
        </div>
      </nav>

      <section className="border-b border-[#1a2330] px-5 py-16 md:px-12 md:py-24">
        <div className="max-w-4xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">The Cyclothone platform</div>
          <h1 className="mt-4 text-4xl font-semibold leading-tight md:text-6xl">Understand the whole system before you enter it.</h1>
          <p className="mt-6 max-w-3xl text-sm leading-6 text-[#8a97a8]">
            Cyclothone connects identity, security operations, trust and control, intelligence and AI, and execution into one governed security platform. This public view explains the architecture and the services without exposing customer data or pretending that protected telemetry exists.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <a href="https://customers.cyclothone.online/login" className="border border-[#00d9ff] px-4 py-3 text-[10px] text-[#00d9ff]">Enter customer platform →</a>
            <a href="https://developers.cyclothone.online" className="border border-[#2a3646] px-4 py-3 text-[10px]">Explore developer platform →</a>
          </div>
        </div>
      </section>

      <section id="planes" className="px-5 py-12 md:px-12 md:py-16">
        <div className="mb-8">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">Five planes · fifteen layers</div>
          <h2 className="mt-2 text-3xl font-semibold">The complete public map</h2>
          <p className="mt-2 max-w-3xl text-xs leading-5 text-[#8a97a8]">The layer map is architectural. Service links below lead to protected customer operations; visitors can read what each capability does before authentication.</p>
        </div>

        <div className="space-y-6">
          {planes.map((plane, pi) => (
            <section key={plane.name} className="border border-[#1a2330] bg-[#0a0e14]">
              <div className="border-b border-[#1a2330] p-5 md:p-6">
                <div className="text-[9px] uppercase tracking-[.16em] text-[#00d9ff]">Plane {pi + 1}</div>
                <h3 className="mt-1 text-xl font-medium">{plane.name}</h3>
                <p className="mt-2 max-w-3xl text-xs leading-5 text-[#8a97a8]">{plane.description}</p>
              </div>
              <div className="grid gap-px bg-[#1a2330] md:grid-cols-2 xl:grid-cols-3">
                {plane.layers.map(layer => (
                  <article id={"layer-" + layer.id} key={layer.id} className="bg-[#070a0f] p-5">
                    <div className="font-mono text-[10px] text-[#00d9ff]">{layer.id}</div>
                    <h4 className="mt-2 font-medium">{layer.name}</h4>
                    <p className="mt-2 text-xs leading-5 text-[#8a97a8]">{layer.description}</p>
                    <div className="mt-4 space-y-2">
                      {layer.services.length ? layer.services.map(service => (
                        <div key={service.key} className="border-t border-[#1a2330] pt-2">
                          <div className="text-[11px]">{service.name}</div>
                          <div className="mt-1 text-[10px] leading-4 text-[#5a6675]">{service.description}</div>
                          {serviceNames.has(service.key) && (
                            <a href={"https://customers.cyclothone.online/request-service?service=" + encodeURIComponent(service.key)} className="mt-2 inline-block text-[9px] text-[#00d9ff]">Protected service entry →</a>
                          )}
                        </div>
                      )) : <div className="border-t border-[#1a2330] pt-3 text-[10px] text-[#5a6675]">Architecture layer; protected capabilities connect here when authorized.</div>}
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ))}
        </div>
      </section>

      <section id="flow" className="border-y border-[#1a2330] px-5 py-12 md:px-12 md:py-16">
        <div className="max-w-4xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#00ff9d]">Operating boundary</div>
          <h2 className="mt-3 text-3xl font-semibold">AI reasons. Trust verifies. Control authorizes. Execution acts. Evidence proves.</h2>
          <p className="mt-4 text-sm leading-6 text-[#8a97a8]">
            Public visitors can understand the workflow without receiving customer telemetry. Authentication belongs at the protected customer or developer destination, and higher-risk operations remain subject to verification, admission and authorization.
          </p>
        </div>
      </section>

      <footer className="px-5 py-8 text-[10px] text-[#5a6675] md:px-12">
        Cyclothone · Public platform map · No customer telemetry is displayed on this surface.
      </footer>
    </main>
  );
}
