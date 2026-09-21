import Link from "next/link";
import { C } from "@/lib/design/tokens";
import { Panel } from "@/components/design/Panel";

const items = [
  ["agents", "◆"],
  ["models", "▣"],
  ["providers", "⬡"],
  ["missions", "◇"],
  ["tools", "▤"],
  ["runs", "▶"],
  ["budgets", "◐"],
  ["audit", "▦"],
];

export default function Kontrol() {
  return (
    <div className="min-h-screen bg-[#05070a]">
      <header className="flex h-14 items-center justify-between border-b border-[#1a2330] px-6">
        <span className="type-h2">
          Cyclothone <span className="type-label text-[#ff2d55]">/kontrol</span>
        </span>
        <span className="type-code text-[#5a6675]">Internal authority surface</span>
      </header>

      <div className="flex">
        <nav aria-label="Control plane navigation" className="flex w-16 flex-col items-center border-r border-[#1a2330] py-4">
          {items.map(([name, icon]) => (
            <Link
              key={name}
              href={`/kontrol/${name}`}
              aria-label={name}
              className="mb-2 flex h-9 w-9 items-center justify-center border type-code text-[#8a97a8] hover:border-[#ff2d55] hover:text-[#ff2d55]"
            >
              {icon}
            </Link>
          ))}
        </nav>

        <main className="flex-1 p-8">
          <div className="type-label text-[#ff2d55]">Authority</div>
          <h1 className="type-display mt-2">Control plane</h1>
          <p className="mt-3 max-w-2xl type-body text-[#8a97a8]">
            Internal control and execution authority. Operational state is shown only when backed by authenticated control-plane APIs.
          </p>

          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <Panel>
              <div className="type-h2">Authority domains</div>
              <div className="mt-4 space-y-3">
                {["Agents", "Models", "Providers", "Missions", "Tools", "Budgets"].map((x) => (
                  <Link
                    key={x}
                    href={`/kontrol/${x.toLowerCase()}`}
                    className="flex justify-between border-b border-[#1a2330] pb-2 type-code hover:text-[#e8eef6]"
                  >
                    <span>{x}</span>
                    <span className="text-[#5a6675]">Open →</span>
                  </Link>
                ))}
              </div>
            </Panel>

            <Panel glow accent={C.kontrolAccent}>
              <div className="type-h2">Execution authority</div>
              <p className="type-body mt-2 text-[#8a97a8]">
                Kill switches and destructive controls are intentionally unavailable here until their authenticated backend authority route is verified.
              </p>
            </Panel>
          </div>
        </main>
      </div>
    </div>
  );
}
