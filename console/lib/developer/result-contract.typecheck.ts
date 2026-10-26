/**
 * Compile-time regression checks for the public Result Contract.
 * This file is included by the console's strict TypeScript build.
 */
import type {
  NoMatchResult,
  PartialResult,
  ResultContract,
} from "./result-contract";

declare const result: ResultContract;

// @ts-expect-error The contract deliberately has no generic success boolean.
result.success;

// @ts-expect-error A partial result cannot be assigned to a no-match result.
const unsafeNoMatch: NoMatchResult = result as PartialResult;

// @ts-expect-error A partial result must carry at least one explicit coverage gap.
const invalidPartial: PartialResult = {
  schemaVersion: "1.0",
  resultId: "compile-time-only",
  sessionId: "compile-time-only",
  disposition: "partial_coverage",
  gaps: [],
  receipt: {
    receiptId: "compile-time-only",
    schemaVersion: "1.0",
    integrityState: "unsigned",
    issuedAt: "2026-01-01T00:00:00Z",
    evidence: [],
  },
};

void unsafeNoMatch;
void invalidPartial;
