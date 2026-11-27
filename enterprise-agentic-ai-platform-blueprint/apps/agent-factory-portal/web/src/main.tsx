// SPDX-License-Identifier: Apache-2.0
// Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { configureApiClient } from './api/client'
import { loadAuthProvider } from './auth/providerSelection'
import ConfigErrorPage from './config/ConfigErrorPage'
import { loadRuntimeConfig, setRuntimeConfig } from './config/runtimeConfig'

/**
 * Loads `/config.json` before anything renders. A missing or invalid file, or a provider that
 * fails to load, renders the configuration error page; nothing throws at module load.
 */
async function start() {
  const root = createRoot(document.getElementById('root')!)
  const result = await loadRuntimeConfig()
  if (!result.ok) {
    root.render(<ConfigErrorPage errors={result.errors} />)
    return
  }
  try {
    setRuntimeConfig(result.config)
    configureApiClient(result.config.apiBaseUrl)
    const AuthProvider = await loadAuthProvider(result.config)
    root.render(
      <StrictMode>
        <App config={result.config} AuthProvider={AuthProvider} />
      </StrictMode>,
    )
  } catch (err) {
    const message = err instanceof Error ? err.message : 'The sign-in provider could not be started.'
    root.render(<ConfigErrorPage errors={[message]} />)
  }
}

void start()
