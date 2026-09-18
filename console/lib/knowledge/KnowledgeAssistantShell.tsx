"use client";

import { usePathname } from "next/navigation";
import { Assistant } from "@/lib/knowledge/Assistant";

export function KnowledgeAssistantShell() {
  const pathname = usePathname();
  return <Assistant page={pathname || "/"} />;
}
