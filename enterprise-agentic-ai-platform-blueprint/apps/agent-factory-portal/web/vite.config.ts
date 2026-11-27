// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { rm } from 'node:fs/promises'
import { resolve } from 'node:path'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/postcss'

/**
 * Runtime configuration is written by infrastructure next to the bundle as `/config.json`.
 * The copies and the example in `public/` are for `npm run dev` only, so they never ship in `dist/`.
 */
function dropLocalRuntimeConfig(): Plugin {
  return {
    name: 'drop-local-runtime-config',
    apply: 'build',
    async closeBundle() {
      for (const name of ['config.json', 'config.local.json', 'config.example.json']) {
        await rm(resolve(import.meta.dirname, 'dist', name), { force: true })
      }
    },
  }
}

export default defineConfig({
  plugins: [react(), dropLocalRuntimeConfig()],
  // Configured here rather than in a postcss.config.js: the repository ignores *.js files.
  css: { postcss: { plugins: [tailwindcss()] } },
  server: {
    // Local development against a back end on another port: requests to /api are forwarded
    // when AFP_DEV_API_TARGET is set (for example http://localhost:8000).
    proxy: process.env.AFP_DEV_API_TARGET
      ? { '/api': { target: process.env.AFP_DEV_API_TARGET, changeOrigin: true } }
      : undefined,
  },
})
