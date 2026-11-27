# Agent Factory Portal: web front end

The Agent Factory Portal is the product surface of the Enterprise Agentic AI Platform Blueprint.
This directory holds its web front end: a single-page application built with React, Vite and
Tailwind CSS.

**Read-only by default.** It covers the assurance and operations plane and the governance
catalog. No screen offers an action that changes an agent, a tool gateway, a policy or a
Workstream cell: those change through code, descriptors and pipelines.

**Governed registration and approval** is an optional feature, off unless
`features.governedActions` is `true` in `/config.json`. It records an agent's governance
document and the decision on it; it deploys nothing. Every write goes through one module,
`src/actions/registrationsClient.ts`, to `/registrations` only. A test (`src/hygiene.test.ts`)
fails the build if a write is added anywhere else, or if anything outside `src/actions/`
imports that folder other than through the one flagged dynamic import.

## Screens

| Plane | Screen | Route |
|-------|--------|-------|
| Assurance and operations | Fleet (home): counts, cell health, recent agents | `/` |
| | Agents: list and detail (Overview, Tool subscriptions, Deployment, Traces, Cost, Release evidence) | `/agents`, `/agents/:id` |
| | Tool gateways: list and detail (Overview, Tools, Policies, Connected agents) | `/tool-gateways`, `/tool-gateways/:id` |
| | Access graph | `/access-graph` |
| | Observability | `/observability` |
| | Release evidence | `/release-evidence`, `/release-evidence/:agentId` |
| Platform control | Governance catalog: Agents, Tools, Guardrail profiles, Models | `/catalog/:section` |
| | Registrations: list, register, record page with history (feature flag) | `/registrations`, `/registrations/new`, `/registrations/:id`, `/registrations/:id/edit` |
| | Approvals queue (feature flag, approver authority) | `/approvals` |
| Resources | Documentation | `/docs` |

`/auth/callback` is the sign-in redirect target.

## Runtime configuration

Nothing is configured at build time. The deployed site serves `/config.json`, written by
infrastructure next to the bundle, and the application loads it before it renders:

```json
{
  "apiBaseUrl": "/api/v1",
  "authProvider": "cognito",
  "cognito": {
    "authority": "https://cognito-idp.<region>.amazonaws.com/<userPoolId>",
    "clientId": "<appClientId>",
    "domain": "https://<prefix>.auth.<region>.amazoncognito.com",
    "scopes": ["openid", "email", "profile"]
  },
  "entra": { "tenantId": "<tenantId>", "clientId": "<spaClientId>", "apiScope": "api://<apiAppId>/access_as_user" },
  "environment": "nonprod",
  "features": { "readOnly": true, "governedActions": false }
}
```

- `apiBaseUrl`: an `https` URL or a same-origin path. It includes `/api/v1`.
- `authProvider`: `cognito` or `entra`. Only the matching block is required.
- `environment`: `nonprod` or `prod`; shown in the sidebar.
- `features.governedActions`: `true` enables the registration and approval screens. Anything
  else leaves them off, and then their code is never downloaded and only `GET` requests are made.
- A missing file, invalid JSON, or a value that is empty or still a `<placeholder>` shows a
  configuration error page that names each problem. The application never starts half
  configured.

If `/config.json` is absent, the application falls back to `/config.local.json`, which is meant
for local development. Both files and the example are removed from `dist/` at build time, so a
build never ships a local configuration.

## Sign-in

The provider is chosen by `authProvider`, and only that provider's library is downloaded.

- **Amazon Cognito** (`oidc-client-ts`): authorization code flow with PKCE against the hosted UI.
  The ID token is sent to the API as the bearer token, because the API's JWT authorizer checks
  the app client id as the audience. Sign-out goes to
  `<domain>/logout?client_id=…&logout_uri=…`. Groups from the `cognito:groups` claim are shown in
  the profile menu for reference; the API decides the role.
- **Microsoft Entra ID** (MSAL): the access token for `entra.apiScope` is sent to the API.

Register `https://<site>/auth/callback` as the redirect URL and `https://<site>/` as the sign-out
URL. The session is kept in session storage and ends with the tab. No token is written to local
storage.

## Run locally against a back end

Requires Node.js 22 or later.

```bash
npm ci
cp public/config.example.json public/config.local.json   # then fill in the values
npm run dev                                              # http://localhost:5173
```

To reach an API on another port without CORS, keep `"apiBaseUrl": "/api/v1"` and let the
development server forward `/api`:

```bash
AFP_DEV_API_TARGET=http://localhost:8000 npm run dev
```

Alternatively set `apiBaseUrl` to the API's full URL (`http` is accepted for `localhost` only)
and allow the development origin in the API's CORS settings.

Add `http://localhost:5173/auth/callback` and `http://localhost:5173/` to the identity
provider's redirect and sign-out URLs for local sign-in. `public/config.local.json` and
`public/config.json` are ignored by git.

## Build and check

```bash
npm run typecheck   # tsc -b
npm run lint        # eslint
npm test            # vitest, unit tests in src/**/*.test.ts
npm run build       # typecheck, then vite build into dist/
```

`dist/` is static: upload it to the site bucket and write `/config.json` beside it. The host
must answer unknown paths with `index.html`. The application calls only the configured API and
identity provider; it loads no font, script or image from a third party.

## Accessibility

`axe-core` is a development dependency so the same version can be run against the built site
from a headless browser. Every route was checked with it in a signed-in state, with governed
actions on, and reported no violation. Things to keep when changing the UI:

- every control has a visible focus ring (`:focus-visible` in `src/index.css`) and a name;
- the first Tab stop is a "Skip to main content" link;
- the access graph has a Table view with the same relationships and the same detail panel;
- definition lists are `<dl>` with `<div>` groups of one `<dt>` and `<dd>` (use `Field`);
- text on a light background uses `slate-600` or darker.

## API

Every request the front end makes, with its response type, is listed in
[API_CONTRACT.md](API_CONTRACT.md). The typed client is `src/api/client.ts`.

## Layout

```
src/
  main.tsx                 loads /config.json, selects the sign-in provider, renders
  config/                  runtime configuration loader and the error page
  auth/                    provider-neutral context and token broker
    cognito/               Amazon Cognito provider (the only importer of oidc-client-ts)
    entra/                 Microsoft Entra ID provider (the only importer of MSAL)
  api/                     typed read-only client and 401 handling
  actions/                 governed registration and approval (loaded only when enabled)
  components/              screens, grouped as in the navigation
```

## Licence and origin

Parts of this front end are derived from the Agentic Governance Platform (Apache-2.0). Those
files carry `SPDX-License-Identifier: Apache-2.0` and a notice that they were modified; files
written for the portal carry `SPDX-License-Identifier: MIT-0`. See [`../NOTICE`](../NOTICE) and
[`../THIRD_PARTY.md`](../THIRD_PARTY.md).
