"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function CustomerOnboardingRedirect() {
  const router = useRouter();
  useEffect(() => { router.replace("/customer/overview"); }, [router]);
  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6] grid place-items-center"><p className="text-sm text-[#8a97a8]">Opening your Cyclothone workspace…</p></main>;
}
