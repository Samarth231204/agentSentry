import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentGuard",
  description: "Test your AI agent for security weaknesses, on your own machine.",
};

function ShieldMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 6.5v8.6c0 7.4 5 13.9 12 15.9 7-2 12-8.5 12-15.9V6.5z" fill="#1d5fd6" />
      <path d="M10.5 16.2l3.6 3.6 7.4-7.6" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <Link href="/" className="brand">
            <ShieldMark />
            AgentGuard
          </Link>
          <nav className="topnav" aria-label="Main">
            <Link href="/onboarding">Get started</Link>
            <Link href="/">Runs</Link>
            <Link href="/new">New test</Link>
            <Link href="/settings">Settings</Link>
          </nav>
        </header>
        <main className="container">{children}</main>
        <footer className="footer">AgentGuard runs on this machine. Your code is read, not changed, and API keys stay local.</footer>
      </body>
    </html>
  );
}
