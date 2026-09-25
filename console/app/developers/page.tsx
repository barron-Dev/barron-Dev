import Link from "next/link";

export default function Developers() {
  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex min-h-14 items-center justify-between border-b border-[#1a2330] bg-[#0a0e14] px-6 py-3">
        <div><span className="font-semibold">Cyclothone</span><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#00ff9d]">Developer</span></div>
        <Link href="/developers/playground" className="border border-[#00ff9d] px-3 py-2 text-[10px] text-[#00ff9d]">Open playground →</Link>
      </header>

      <div className="mx-auto max-w-5xl px-6 py-12">
        <div className="max-w-2xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">Developer platform</div>
          <h1 className="mt-2 text-3xl font-semibold">Build with Cyclothone.</h1>
          <p className="mt-3 text-sm leading-6 text-[#8a97a8]">Use the trust API to integrate governed AI workloads. Start with the API contract, then test a real request.</p>
        </div>

        <div className="mt-10 grid gap-4 md:grid-cols-3">
          <a href="#api" className="border border-[#2a3646] bg-[#0a0e14] p-5 hover:border-[#00ff9d]"><div className="text-[10px] uppercase tracking-[.15em] text-[#00ff9d]">01</div><h2 className="mt-2 font-medium">API</h2><p className="mt-2 text-xs leading-5 text-[#8a97a8]">The governed API entry point for durable AI runs.</p></a>
          <Link href="/developers/playground" className="border border-[#2a3646] bg-[#0a0e14] p-5 hover:border-[#00ff9d]"><div className="text-[10px] uppercase tracking-[.15em] text-[#00ff9d]">02</div><h2 className="mt-2 font-medium">Playground</h2><p className="mt-2 text-xs leading-5 text-[#8a97a8]">Send a real API request and inspect the response.</p></Link>
          <a href="https://customers.cyclothone.online/login" className="border border-[#2a3646] bg-[#0a0e14] p-5 hover:border-[#ffb347]"><div className="text-[10px] uppercase tracking-[.15em] text-[#ffb347]">03</div><h2 className="mt-2 font-medium">Account</h2><p className="mt-2 text-xs leading-5 text-[#8a97a8]">Sign in with your Cyclothone account before using protected access.</p></a>
        </div>

        <section id="api" className="mt-10 border border-[#1a2330] bg-[#0a0e14] p-6">
          <div className="text-[10px] uppercase tracking-[.15em] text-[#5a6675]">API contract</div>
          <div className="mt-3 flex flex-wrap items-center gap-3"><span className="border border-[#00ff9d] px-2 py-1 font-mono text-[10px] text-[#00ff9d]">POST</span><code className="font-mono text-xs">/api/v1/ai/run</code></div>
          <p className="mt-3 text-xs leading-5 text-[#8a97a8]">A production run requires a real execution binding: mission, version, hash, provider/model binding and idempotency token. Incomplete configuration is rejected.</p>
          <div className="mt-5 overflow-auto border border-[#1a2330] p-4"><pre className="font-mono text-[11px] leading-5 text-[#8a97a8]">{JSON.stringify({workload_layer:"customer",risk_level:"LOW",mission_id:"uuid",mission_version:1,mission_hash:"sha256...",idempotency_token:"unique-request"},null,2)}</pre></div>
        </section>
      </div>
    </main>
  );
}