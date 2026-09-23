"use client";

import type { ReactNode } from "react";

type Row = Record<string, unknown>;

export function ServiceLoading({ label = "Loading live service data…" }: { label?: string }) {
  return <div className="border border-[#1a2330] bg-[#0a0e14] p-5 text-xs text-[#8a97a8]" role="status">{label}</div>;
}

export function ServiceError({ message }: { message: string }) {
  return <div className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-xs text-[#ff6b83]" role="alert">{message}</div>;
}

export function ServiceEmpty({ title = "No operational records", detail = "The service returned no records for this tenant." }: { title?: string; detail?: string }) {
  return (
    <div className="border border-dashed border-[#2a3646] bg-[#0a0e14] p-8 text-center">
      <div className="text-sm font-medium text-[#e8eef6]">{title}</div>
      <p className="mt-2 text-xs text-[#5a6675]">{detail}</p>
    </div>
  );
}

function scalar(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

export function ServiceTable({ rows, columns, empty }: { rows: Row[]; columns: Array<{ key: string; label: string }>; empty?: ReactNode }) {
  if (!rows.length) return <>{empty ?? <ServiceEmpty />}</>;
  return (
    <div className="overflow-auto border border-[#1a2330]">
      <table className="w-full min-w-[720px] text-left text-[11px]">
        <thead className="bg-[#111823] text-[9px] uppercase tracking-[.12em] text-[#5a6675]">
          <tr>{columns.map(c => <th key={c.key} className="border-b border-[#1a2330] px-3 py-2">{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={String(row.id ?? index)} className="border-b border-[#1a2330] last:border-0">
              {columns.map(c => <td key={c.key} className="max-w-[360px] truncate px-3 py-2 font-mono text-[#8a97a8]" title={scalar(row[c.key])}>{scalar(row[c.key])}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ServiceSection({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold">{title}</h2>
        {typeof count === "number" && <span className="font-mono text-[10px] text-[#5a6675]">{count}</span>}
      </div>
      {children}
    </section>
  );
}
