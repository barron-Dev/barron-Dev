/**
 * Cyclothone developer Result Contract v1.
 *
 * Security invariant: callers must branch on the disposition. There is no
 * generic `success: boolean` because it cannot express incomplete coverage.
 *
 * These are public contract types, not evidence that a live scan ran. A
 * receipt is trusted only after the server-side verification path validates it.
 */

export type IntegrityState =
  | "unsigned"
  | "signed"
  | "verified"
  | "invalid"
  | "unavailable";

export type VerificationState =
  | "verified"
  | "inferred"
  | "unverified"
  | "invalid"
  | "unavailable";

export interface EvidenceReference {
  evidenceId: string;
  sourceId: string;
  collectedAt: string | null;
  parserVersion: string | null;
  contentSha256: string | null;
  verificationState: VerificationState;
}

export interface ReceiptBase {
  receiptId: string;
  schemaVersion: "1.0";
  integrityState: IntegrityState;
  issuedAt: string;
  evidence: EvidenceReference[];
}

export interface CompletedScope {
  /** Explicitly enumerated scope that actually completed. */
  serviceIds: string[];
  startedAt: string;
  completedAt: string;
  coverageUntil: string | null;
}

export interface CoverageGap {
  serviceId: string;
  reason:
    | "source_unavailable"
    | "not_attempted"
    | "blocked_by_policy"
    | "failed"
    | "stale"
    | "unsupported";
  detail?: string;
}

export interface FindingReference {
  findingId: string;
  severity: "info" | "low" | "medium" | "high" | "critical" | "unknown";
  evidenceIds: string[];
}

export interface ExecError {
  code: string;
  message: string;
  retryable: boolean;
}

export interface ExposedResult {
  schemaVersion: "1.0";
  resultId: string;
  sessionId: string;
  disposition: "exposed";
  findings: [FindingReference, ...FindingReference[]];
  receipt: ReceiptBase;
}

export interface NoMatchResult {
  schemaVersion: "1.0";
  resultId: string;
  sessionId: string;
  disposition: "no_match_in_completed_scope";
  scope: CompletedScope;
  receipt: ReceiptBase;
}

export interface PartialResult {
  schemaVersion: "1.0";
  resultId: string;
  sessionId: string;
  disposition: "partial_coverage";
  /** Findings may coexist with gaps; partial coverage must never erase a hit. */
  findings: FindingReference[];
  gaps: [CoverageGap, ...CoverageGap[]];
  receipt: ReceiptBase;
}

export interface BlockedResult {
  schemaVersion: "1.0";
  resultId: string;
  sessionId: string;
  disposition: "blocked";
  reason: string;
  findings: FindingReference[];
  receipt: ReceiptBase;
}

export interface FailedResult {
  schemaVersion: "1.0";
  resultId: string;
  sessionId: string;
  disposition: "failed";
  error: ExecError;
  findings: FindingReference[];
  receipt: ReceiptBase;
}

export type ResultContract =
  | ExposedResult
  | NoMatchResult
  | PartialResult
  | BlockedResult
  | FailedResult;

export class NotSafeError extends Error {
  readonly result: Exclude<ResultContract, NoMatchResult>;

  constructor(result: Exclude<ResultContract, NoMatchResult>) {
    super(
      `Cyclothone result is '${result.disposition}', not a completed no-match result.`,
    );
    this.name = "NotSafeError";
    this.result = result;
  }
}

/**
 * Assert that a result is a verified no-match for its explicitly completed
 * scope at the caller-supplied evaluation time. Requiring the time as input
 * keeps replay decisions deterministic. This does not authorize actions.
 */
export function assertSafe(
  result: ResultContract,
  evaluatedAt: string,
): asserts result is NoMatchResult {
  if (result.disposition !== "no_match_in_completed_scope") {
    throw new NotSafeError(result as Exclude<ResultContract, NoMatchResult>);
  }

  const evaluatedAtMs = Date.parse(evaluatedAt);
  const startedAtMs = Date.parse(result.scope.startedAt);
  const completedAtMs = Date.parse(result.scope.completedAt);

  if (
    result.scope.serviceIds.length === 0 ||
    !Number.isFinite(startedAtMs) ||
    !Number.isFinite(completedAtMs) ||
    !Number.isFinite(evaluatedAtMs) ||
    completedAtMs < startedAtMs
  ) {
    throw new Error("No-match result does not contain a valid completed scope or evaluation time.");
  }

  if (result.receipt.integrityState !== "verified") {
    throw new Error(
      `No-match receipt integrity is '${result.receipt.integrityState}', not verified.`,
    );
  }

  if (
    result.scope.coverageUntil &&
    Date.parse(result.scope.coverageUntil) < evaluatedAtMs
  ) {
    throw new Error("No-match result is stale at the supplied evaluation time.");
  }
}

/** Require an exhaustive branch whenever a caller handles a result. */
export function assertNever(value: never): never {
  throw new Error(`Unhandled Cyclothone result disposition: ${String(value)}`);
}
