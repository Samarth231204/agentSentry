import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentGuard",
  description: "Local security dashboard for AI agent runs",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <Link href="/" className="brand">
            AgentGuard
          </Link>
          <span className="muted small">local dashboard · 127.0.0.1 only</span>
        </header>
        <main className="container">{children}</main>
      </body>
    </html>
  );
}
