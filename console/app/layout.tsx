import type { Metadata } from "next";
import "./globals.css";
import { KnowledgeAssistantShell } from "../lib/knowledge/KnowledgeAssistantShell";
import { ApiAuthPrompt } from "../components/ApiAuthPrompt";

export const metadata: Metadata = {
  title: "Cyclothone",
  description: "Cyclothone security operations platform",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        {children}
        <KnowledgeAssistantShell />
        <ApiAuthPrompt />
      </body>
    </html>
  );
}
