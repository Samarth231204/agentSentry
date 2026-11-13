import { fileURLToPath } from "node:url";

/** @type {import('next').NextConfig} */
// All run pages use query strings (/run?id=...) instead of dynamic segments,
// so the app can later be exported as static files without changes.
const nextConfig = {
  reactStrictMode: true,
  // Pin the workspace root to this folder; a lockfile elsewhere on the machine
  // would otherwise be picked as the root.
  outputFileTracingRoot: fileURLToPath(new URL(".", import.meta.url)),
};

export default nextConfig;
