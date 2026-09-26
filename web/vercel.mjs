import { deploymentEnv, routes } from "@vercel/config/v1";

const modalOrigin = deploymentEnv("MODAL_API_ORIGIN");

export const config = {
  framework: "vite",
  installCommand: "npm ci",
  buildCommand: "npm run build",
  outputDirectory: "dist",
  rewrites: [
    routes.rewrite("/api/:path*", `${modalOrigin}/:path*`),
    // Vercel injects Web Analytics and other platform routes under /_vercel.
    // Keep that reserved namespace out of the SPA fallback so those handlers
    // can serve JavaScript and receive events instead of returning index.html.
    routes.rewrite("/:path((?!_vercel/).*)", "/index.html"),
  ],
  headers: [
    {
      source: "/api/:path*",
      headers: [{ key: "Cache-Control", value: "private, no-store" }],
    },
  ],
};
