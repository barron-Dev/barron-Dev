"use client";

import { useEffect, useState } from "react";

type Hint = {
  title: string;
  body_md: string;
  guide_slug?: string | null;
  doc_url?: string | null;
  api_url?: string | null;
};

type SearchResult = {
  node_id: string;
  kind: string;
  label: string;
  summary?: string | null;
  deep_link: string;
  score: number;
};

type SearchResponse = {
  intent: string;
  confidence: number;
  count: number;
  results: SearchResult[];
  grouped: Record<string, SearchResult[]>;
  suggested_actions: { label: string; url: string }[];
};

export function Assistant({ page }: { page: string }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<SearchResponse | null>(null);
  const [hints, setHints] = useState<Record<string, Hint>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void fetch(
      `/api/proxy/v1/knowledge/hints?route=${encodeURIComponent(page)}`,
      { signal: controller.signal },
    )
      .then(async (response) => {
        if (!response.ok) throw new Error("Context hints unavailable");
        return response.json() as Promise<Record<string, Hint>>;
      })
      .then(setHints)
      .catch((cause: unknown) => {
        if ((cause as { name?: string })?.name !== "AbortError") {
          setError("Knowledge service unavailable");
        }
      });
    return () => controller.abort();
  }, [page]);

  async function runSearch(value = query) {
    const q = value.trim();
    if (!q || loading) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/proxy/v1/knowledge/search?q=${encodeURIComponent(q)}&limit=30`,
      );
      if (!response.ok) throw new Error("Knowledge search unavailable");
      setResult((await response.json()) as SearchResponse);
    } catch {
      setError("Knowledge service unavailable");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="fixed bottom-6 right-6 z-40 flex h-12 w-12 items-center justify-center rounded-full border border-border-subtle bg-surface text-text-primary shadow-lg"
        aria-label={open ? "Close Cyclothone Guide" : "Open Cyclothone Guide"}
        aria-expanded={open}
      >
        <span aria-hidden="true">?</span>
      </button>

      {open && (
        <aside
          aria-label="Cyclothone Guide"
          className="fixed bottom-24 right-6 z-40 flex max-h-[70vh] w-[min(420px,calc(100vw-3rem))] flex-col overflow-hidden rounded-xl border border-border-subtle bg-surface shadow-xl"
        >
          <header className="flex items-center border-b border-border-subtle px-4 py-3">
            <div>
              <div className="text-sm font-semibold text-text-primary">
                Cyclothone Guide
              </div>
              <div className="text-[10px] uppercase tracking-wider text-text-disabled">
                Context · Search · Guides
              </div>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="ml-auto text-text-tertiary hover:text-text-primary"
              aria-label="Close"
            >
              ×
            </button>
          </header>

          <div className="border-b border-border-subtle p-3">
            <label className="sr-only" htmlFor="cyclothone-knowledge-query">
              Search Cyclothone knowledge
            </label>
            <input
              id="cyclothone-knowledge-query"
              value={query}
              maxLength={300}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void runSearch();
              }}
              placeholder="Search antivirus, pricing, API…"
              className="h-9 w-full rounded border border-border-subtle bg-inset px-3 text-sm text-text-primary outline-none focus:border-accent"
              autoFocus
            />
          </div>

          <div className="flex-1 space-y-4 overflow-y-auto p-3">
            {error && (
              <div role="alert" className="border-l-2 border-critical px-3 py-2 text-xs text-text-secondary">
                {error}
              </div>
            )}

            {!result && Object.keys(hints).length > 0 && (
              <section>
                <div className="mb-2 text-[10px] uppercase tracking-wider text-text-disabled">
                  On this page
                </div>
                <div className="space-y-3">
                  {Object.entries(hints).map(([key, hint]) => (
                    <div key={key} className="border-b border-border-subtle pb-3 last:border-0">
                      <div className="text-xs font-medium text-text-secondary">{hint.title}</div>
                      <div className="mt-1 line-clamp-3 text-xs text-text-tertiary">{hint.body_md}</div>
                      {hint.guide_slug && (
                        <a href={`/guides/${hint.guide_slug}`} className="mt-1 inline-block text-xs text-accent">
                          Open guide →
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </section>
            )}

            {loading && <div className="text-xs text-text-tertiary">Searching…</div>}

            {result && (
              <section aria-live="polite" className="space-y-4">
                <div className="text-[10px] uppercase tracking-wider text-text-disabled">
                  {result.count} results · {result.intent} · {Math.round(result.confidence * 100)}% intent confidence
                </div>

                {result.suggested_actions.length > 0 && (
                  <div className="space-y-1">
                    {result.suggested_actions.map((action) => (
                      <a
                        key={action.url}
                        href={action.url}
                        className="block rounded border border-accent/30 bg-accent/10 px-3 py-2 text-xs text-accent"
                      >
                        {action.label} →
                      </a>
                    ))}
                  </div>
                )}

                {Object.entries(result.grouped).map(([kind, items]) => (
                  <section key={kind}>
                    <div className="mb-1 text-[10px] uppercase tracking-wider text-text-disabled">
                      {kind}
                    </div>
                    <div className="space-y-1">
                      {items.map((item) => (
                        <a
                          key={item.node_id}
                          href={item.deep_link}
                          className="block rounded border-b border-border-subtle px-2 py-2 hover:bg-elevated"
                        >
                          <div className="text-xs font-medium text-text-primary">{item.label}</div>
                          {item.summary && (
                            <div className="mt-0.5 line-clamp-2 text-xs text-text-tertiary">
                              {item.summary}
                            </div>
                          )}
                        </a>
                      ))}
                    </div>
                  </section>
                ))}
              </section>
            )}

            {!result && !loading && !error && Object.keys(hints).length === 0 && (
              <div className="text-xs text-text-tertiary">
                Search the Cyclothone knowledge graph to find services, APIs, guides, and concepts.
              </div>
            )}
          </div>
        </aside>
      )}
    </>
  );
}

export function Hint({
  k,
  children,
  onHint,
}: {
  k: string;
  children: React.ReactNode;
  onHint?: (key: string) => void;
}) {
  return (
    <span className="inline-flex items-center gap-1">
      {children}
      <button
        type="button"
        aria-label={`Explain ${k}`}
        className="inline-flex h-3.5 w-3.5 items-center justify-center rounded-full border border-text-disabled text-[9px] leading-none text-text-disabled"
        onClick={() => onHint?.(k)}
      >
        ?
      </button>
    </span>
  );
}
