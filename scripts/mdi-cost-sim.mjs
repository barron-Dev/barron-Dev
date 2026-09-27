#!/usr/bin/env node
const args = new Set(process.argv.slice(2));
const numbers = args.has('--scenario=1M-numbers') ? 1_000_000 : 100_000;
const providerCallsPerNumber = 2;
const providerCostUsd = 0.0015;
const monthlyUsd = numbers * providerCallsPerNumber * providerCostUsd;
const ceiling = 5000;
const result = { numbers, provider_calls: numbers * providerCallsPerNumber, monthly_usd: Number(monthlyUsd.toFixed(2)), ceiling_usd: ceiling };
console.log(JSON.stringify(result));
if (monthlyUsd > ceiling) process.exit(1);
