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
          <nav className="topnav" aria-label="Main">
            <Link href="/">Runs</Link>
            <Link href="/new">New run</Link>
            <Link href="/settings">Settings</Link>
            <Link href="/onboarding">Set up key</Link>
          </nav>
        </header>
        <main className="container">{children}</main>
      </body>
    </html>
  );
}
