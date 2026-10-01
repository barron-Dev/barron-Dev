export type Adj = Map<string, Array<{ to: string; w: number; conf: number; kind: string }>>;

export function buildAdjacency(
  edges: Array<{ src: string; dst: string; weight: number; confidence: number; kind: string }>,
  directed = false,
): Adj {
  const adj: Adj = new Map();
  const push = (a: string, b: string, e: { weight: number; confidence: number; kind: string }) => {
    if (!adj.has(a)) adj.set(a, []);
    adj.get(a)!.push({ to: b, w: e.weight, conf: e.confidence, kind: e.kind });
  };
  for (const e of edges) {
    push(e.src, e.dst, e);
    if (!directed) push(e.dst, e.src, e);
    if (directed && !adj.has(e.dst)) adj.set(e.dst, []);
  }
  return adj;
}

export function shortestPath(adj: Adj, from: string, to: string, minW = 0.05) {
  const dist = new Map<string, number>([[from, 0]]);
  const prev = new Map<string, { node: string; kind: string }>();
  const visited = new Set<string>();
  const pq = new MinHeap<[number, string]>((a, b) => a[0] - b[0]);
  pq.push([0, from]);

  while (pq.size) {
    const [d, u] = pq.pop()!;
    if (visited.has(u)) continue;
    visited.add(u);
    if (u === to) break;
    for (const e of adj.get(u) ?? []) {
      const eff = e.w * e.conf;
      if (eff < minW) continue;
      const nd = d + 1 / eff;
      if (nd < (dist.get(e.to) ?? Infinity)) {
        dist.set(e.to, nd);
        prev.set(e.to, { node: u, kind: e.kind });
        pq.push([nd, e.to]);
      }
    }
  }
  if (!dist.has(to)) return null;
  const path = [to];
  const kinds: string[] = [];
  let cur = to;
  while (cur !== from) {
    const p = prev.get(cur);
    if (!p) return null;
    kinds.unshift(p.kind);
    path.unshift(p.node);
    cur = p.node;
  }
  return { path, kinds, cost: dist.get(to)! };
}

export function pageRank(adj: Adj, iterations = 30, d = 0.85): Map<string, number> {
  const nodes = [...adj.keys()];
  const N = nodes.length || 1;
  let rank = new Map(nodes.map(n => [n, 1 / N]));
  const outdeg = new Map(nodes.map(n => [n, (adj.get(n) ?? []).length]));
  const inbound = new Map<string, string[]>();
  for (const [u, es] of adj) for (const e of es) {
    if (!inbound.has(e.to)) inbound.set(e.to, []);
    inbound.get(e.to)!.push(u);
  }
  for (let i = 0; i < iterations; i++) {
    const next = new Map<string, number>();
    let dangling = 0;
    for (const n of nodes) if ((outdeg.get(n) ?? 0) === 0) dangling += rank.get(n)!;
    for (const n of nodes) {
      let s = 0;
      for (const p of inbound.get(n) ?? []) s += rank.get(p)! / Math.max(outdeg.get(p) ?? 1, 1);
      next.set(n, (1 - d) / N + d * (s + dangling / N));
    }
    rank = next;
  }
  return rank;
}

export function labelPropagation(adj: Adj, maxIter = 50): Map<string, string> {
  const labels = new Map<string, string>();
  for (const n of adj.keys()) labels.set(n, n);
  const order = [...adj.keys()].sort();
  for (let it = 0; it < maxIter; it++) {
    let changed = 0;
    for (const n of order) {
      const tally = new Map<string, number>();
      for (const e of adj.get(n) ?? []) {
        const label = labels.get(e.to);
        if (!label) continue;
        tally.set(label, (tally.get(label) ?? 0) + e.w * e.conf);
      }
      if (!tally.size) continue;
      const best = [...tally.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
      if (labels.get(n) !== best) { labels.set(n, best); changed++; }
    }
    if (!changed) break;
  }
  return labels;
}

export function jaccard(a: string, b: string, adj: Adj): number {
  const na = new Set((adj.get(a) ?? []).map(e => e.to));
  const nb = new Set((adj.get(b) ?? []).map(e => e.to));
  let inter = 0;
  for (const x of na) if (nb.has(x)) inter++;
  const union = na.size + nb.size - inter;
  return union === 0 ? 0 : inter / union;
}

export function adamicAdar(a: string, b: string, adj: Adj): number {
  const na = new Set((adj.get(a) ?? []).map(e => e.to));
  const nb = new Set((adj.get(b) ?? []).map(e => e.to));
  let s = 0;
  for (const x of na) {
    if (!nb.has(x)) continue;
    const deg = (adj.get(x) ?? []).length;
    if (deg > 1) s += 1 / Math.log(deg);
  }
  return s;
}

export class MinHeap<T> {
  private a: T[] = [];
  constructor(private cmp: (x: T, y: T) => number) {}
  get size() { return this.a.length; }
  push(v: T) {
    this.a.push(v);
    let i = this.a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (this.cmp(this.a[i], this.a[p]) >= 0) break;
      [this.a[i], this.a[p]] = [this.a[p], this.a[i]];
      i = p;
    }
  }
  pop(): T | undefined {
    if (!this.a.length) return undefined;
    const top = this.a[0];
    const last = this.a.pop()!;
    if (this.a.length) {
      this.a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1, r = l + 1;
        let m = i;
        if (l < this.a.length && this.cmp(this.a[l], this.a[m]) < 0) m = l;
        if (r < this.a.length && this.cmp(this.a[r], this.a[m]) < 0) m = r;
        if (m === i) break;
        [this.a[i], this.a[m]] = [this.a[m], this.a[i]];
        i = m;
      }
    }
    return top;
  }
}
