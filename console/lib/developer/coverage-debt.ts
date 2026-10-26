/**
 * Coverage Debt is computed from an authoritative, tenant-scoped asset inventory
 * and each asset's latest eligible result. This module only validates and
 * summarizes supplied counts; it does not fetch or fabricate production data.
 */

export type CoverageBucket =
  | "coveredFreshFull"
  | "stale"
  | "partial"
  | "blocked"
  | "unsupportedAssetType"
  | "failed"
  | "notYetChecked";

export type CoverageBucketCounts = Record<CoverageBucket, number>;

export interface CoverageDebtSummary {
  asOf: string;
  totalAssets: number;
  buckets: CoverageBucketCounts;
  coveredFreshFull: number;
  uncoveredOrUnverified: number;
  coverageDebtPct: number | null;
}

/**
 * Validate that buckets partition the authoritative inventory exactly.
 * Unknown or missing states must be classified explicitly (e.g. notYetChecked),
 * never silently counted as covered.
 */
export function calculateCoverageDebt(
  asOf: string,
  totalAssets: number,
  buckets: CoverageBucketCounts,
): CoverageDebtSummary {
  if (!Number.isFinite(Date.parse(asOf))) {
    throw new Error("Coverage debt requires a valid asOf timestamp.");
  }
  if (!Number.isSafeInteger(totalAssets) || totalAssets < 0) {
    throw new Error("totalAssets must be a non-negative safe integer.");
  }

  for (const [name, count] of Object.entries(buckets)) {
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new Error(`Coverage bucket '${name}' must be a non-negative safe integer.`);
    }
  }

  const classified = Object.values(buckets).reduce((sum, count) => sum + count, 0);
  if (classified !== totalAssets) {
    throw new Error(
      `Coverage buckets (${classified}) must partition totalAssets (${totalAssets}).`,
    );
  }

  const coveredFreshFull = buckets.coveredFreshFull;
  const uncoveredOrUnverified = totalAssets - coveredFreshFull;

  return {
    asOf,
    totalAssets,
    buckets: { ...buckets },
    coveredFreshFull,
    uncoveredOrUnverified,
    coverageDebtPct:
      totalAssets === 0 ? null : (uncoveredOrUnverified / totalAssets) * 100,
  };
}
