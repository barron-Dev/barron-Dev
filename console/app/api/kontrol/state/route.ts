import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Result = { provider: string; status: "ok" | "unknown" | "blocked"; checkedAt: string; source: string; summary: string; details?: unknown };
const repo = "barron-Dev/barron-Dev";
const team = "team_4hcvDltMV6UkqdWnGk8l0ZQN";
const project = "prj_cj6BDOIxylJCXfWcLOlnBtPOvR2x";
const supabaseRef = "whcomikcftbousoqzeal";

function authorized(value: string | null) {
  const expected = process.env.KONTROL_CONSOLE_TOKEN;
  if (!value || !expected) return false;
  const a = Buffer.from(value), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
async function json(url: string, headers: Record<string,string> = {}) {
  const response = await fetch(url, { headers, cache: "no-store", signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error("HTTP " + response.status);
  return response.json() as Promise<any>;
}
async function probe(provider: string, source: string, action: () => Promise<any>, summary: (data: any) => string): Promise<Result> {
  const checkedAt = new Date().toISOString();
  try { const details = await action(); return { provider, status: "ok", checkedAt, source, summary: summary(details), details }; }
  catch (e) { return { provider, status: "unknown", checkedAt, source, summary: e instanceof Error ? e.message : "Provider check failed" }; }
}
export async function GET(req: NextRequest) {
  if (!authorized(req.headers.get("x-kontrol-console-token"))) {
    return NextResponse.json({ error: "Missing or invalid Kontrol read token." }, { status: 401, headers: { "Cache-Control": "no-store" } });
  }
  const checks = await Promise.all([
    probe("GitHub", "GitHub REST API", async () => {
      const h: Record<string,string> = { Accept: "application/vnd.github+json" };
      if (process.env.GITHUB_READ_TOKEN) h.Authorization = "Bearer " + process.env.GITHUB_READ_TOKEN;
      const [r, ref, p] = await Promise.all([
        json("https://api.github.com/repos/" + repo, h),
        json("https://api.github.com/repos/" + repo + "/git/ref/heads/main", h),
        json("https://api.github.com/repos/" + repo + "/pulls?state=open&per_page=100", h),
      ]);
      return { repository: repo, defaultBranch: r.default_branch, mainSha: ref.object?.sha ?? null, lastPushedAt: r.pushed_at, openPullRequests: (Array.isArray(p) ? p : []).map((x: any) => ({ number: x.number, title: x.title, draft: x.draft, head: x.head?.ref, base: x.base?.ref })) };
    }, d => "Repository reachable; main SHA retrieved; " + d.openPullRequests.length + " open pull request(s)."),
    probe("Vercel", "Vercel REST API", async () => {
      if (!process.env.VERCEL_API_TOKEN) throw new Error("VERCEL_API_TOKEN is not configured");
      const d = await json("https://api.vercel.com/v6/deployments?projectId=" + project + "&teamId=" + team + "&limit=5", { Authorization: "Bearer " + process.env.VERCEL_API_TOKEN });
      const rows = Array.isArray(d.deployments) ? d.deployments : [];
      const x = rows[0];
      return { projectId: project, recentCount: rows.length, latest: x ? { id: x.uid, state: x.readyState, target: x.target, createdAt: x.createdAt, url: x.url, commit: x.meta?.githubCommitSha, branch: x.meta?.githubCommitRef } : null };
    }, d => d.latest ? "Latest deployment state: " + (d.latest.state || "unknown") : "No deployment returned."),
    probe("Supabase", "Supabase Management API", async () => {
      if (!process.env.SUPABASE_ACCESS_TOKEN) throw new Error("SUPABASE_ACCESS_TOKEN is not configured");
      const h = { Authorization: "Bearer " + process.env.SUPABASE_ACCESS_TOKEN };
      const [p, m] = await Promise.all([
        json("https://api.supabase.com/v1/projects/" + supabaseRef, h),
        json("https://api.supabase.com/v1/projects/" + supabaseRef + "/database/migrations", h),
      ]);
      if (!Array.isArray(m)) throw new Error("Unexpected migrations response format; migration state is unknown");
      return { projectRef: supabaseRef, status: p.status, region: p.region, migrationCount: m.length, latestMigration: m.length ? m[m.length - 1] : null };
    }, d => "Project metadata reachable; " + d.migrationCount + " migration record(s) returned."),
  ]);
  checks.push({ provider: "Railway", status: "blocked", checkedAt: new Date().toISOString(), source: "operator_report", summary: "Checks intentionally deferred until the Railway trial is upgraded.", details: { liveChecked: false, nextAction: "After upgrade, inspect service identity, deployment history, runtime logs, variable names/presence, and health endpoint before proposing any repair." } });
  return NextResponse.json({ generatedAt: new Date().toISOString(), mode: "read-only", results: checks }, { headers: { "Cache-Control": "no-store, max-age=0", Pragma: "no-cache" } });
}
