import { fileURLToPath } from "node:url";

/** @type {import('next').NextConfig} */
// All run pages use query strings (/run?id=...) instead of dynamic segments,
// so the app can later be exported as static files without changes.
const nextConfig = {
  reactStrictMode: true,
  // Static export: `scripts/build_dashboard.sh` copies the result into the Python package,
  // so `agentguard up` can serve the dashboard without Node. Dev (`npm run dev`) is unchanged.
  output: "export",
  trailingSlash: true,
  // Pin the workspace root to this folder; a lockfile elsewhere on the machine
  // would otherwise be picked as the root.
  outputFileTracingRoot: fileURLToPath(new URL(".", import.meta.url)),
};

export default nextConfig;
