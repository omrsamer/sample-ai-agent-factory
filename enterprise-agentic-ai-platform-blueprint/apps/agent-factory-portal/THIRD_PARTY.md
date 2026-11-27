# Agent Factory Portal: third-party origin and dependencies

## Derived source: Agentic Governance Platform

| | |
|---|---|
| Project | Agentic Governance Platform |
| Part used | Control-plane front end (React single-page application) |
| License | Apache License, Version 2.0 |
| Upstream commit | `d645fffe` |
| Location in this repository | `apps/agent-factory-portal/web/` |
| Status | Modified; maintained independently of the upstream project |

The web front end started as a copy of the upstream console at the commit above and was then
reshaped into the read-only first milestone of the Agent Factory Portal. The copy does not track
upstream: later upstream changes are not merged automatically, and changes made here are not
contributed back by default.

### What changed

- **Removed:** the operations section, studio, repositories and templates; the marketplace; the
  administration screens; the registration wizards; design-only placeholder pages and their
  fixture data; the test-invoke panel; access-grant, containment and policy editing; the embedded
  third-party observability console; every mutating API call.
- **Rewritten:** configuration (runtime `/config.json` instead of build-time variables); the
  authentication layer (a provider-neutral token broker, with Amazon Cognito added alongside
  Microsoft Entra ID); navigation, the home screen, the agent and tool gateway detail pages, the
  policy view, the documentation page.
- **Adapted in place:** the access graph, the observability dashboard, the cost, trace and
  evaluation views, the shared badges and avatar, the 401 retry helpers, the ARN masking helper.
- **Added:** fleet health, the governance catalog (tools, guardrail profiles, models), the
  release evidence screen, the deployment tab, the configuration error page.

### How files are marked

| Header | Meaning |
|---|---|
| `SPDX-License-Identifier: Apache-2.0` and `Derived from Agentic Governance Platform (Apache-2.0); modified for the Agent Factory Portal.` | Derived from upstream and modified. Remains under Apache-2.0. |
| `Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.` and `SPDX-License-Identifier: MIT-0` | Written for the portal. MIT-0, as the rest of this repository. |

JSON files carry no header. The text of the Apache License, Version 2.0 is in
[`web/LICENSE-APACHE-2.0`](web/LICENSE-APACHE-2.0). The upstream attribution notices that
pertain to the front end are reproduced in [`NOTICE`](NOTICE).

## Direct dependencies of the web front end

Versions are the ones resolved in `web/package-lock.json` when this file was written. Every
package is installed from the public npm registry. Transitive dependencies carry their own
notices in their own distributions; the production dependency tree resolves to MIT, ISC,
BSD-3-Clause and Apache-2.0 licensed packages only.

### Runtime (distributed in the bundle)

| Package | Version | License | Source |
|---|---|---|---|
| `@azure/msal-browser` | 5.30.0 | MIT | https://github.com/AzureAD/microsoft-authentication-library-for-js |
| `@azure/msal-react` | 5.8.3 | MIT | https://github.com/AzureAD/microsoft-authentication-library-for-js |
| `@xyflow/react` | 12.12.1 | MIT | https://github.com/xyflow/xyflow |
| `axios` | 1.21.1 | MIT | https://github.com/axios/axios |
| `dagre` | 0.8.5 | MIT | https://github.com/dagrejs/dagre |
| `oidc-client-ts` | 3.5.0 | Apache-2.0 | https://github.com/authts/oidc-client-ts |
| `react` | 19.3.1 | MIT | https://github.com/facebook/react |
| `react-dom` | 19.3.1 | MIT | https://github.com/facebook/react |
| `react-is` | 19.3.1 | MIT | https://github.com/facebook/react |
| `react-router-dom` | 7.18.7 | MIT | https://github.com/remix-run/react-router |
| `recharts` | 3.11.2 | MIT | https://github.com/recharts/recharts |

`oidc-client-ts` is new in the portal. The others are inherited from upstream. Only the library
of the configured sign-in provider is downloaded by a browser: `oidc-client-ts` for Amazon
Cognito, the MSAL packages for Microsoft Entra ID.

### Build and test (not distributed, except generated CSS)

| Package | Version | License | Source |
|---|---|---|---|
| `@eslint/js` | 9.39.5 | MIT | https://github.com/eslint/eslint |
| `@tailwindcss/postcss` | 4.3.5 | MIT | https://github.com/tailwindlabs/tailwindcss |
| `@types/dagre` | 0.7.54 | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |
| `@types/node` | 24.19.4 | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |
| `@types/react` | 19.3.3 | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |
| `@types/react-dom` | 19.3.0 | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |
| `@vitejs/plugin-react` | 6.3.0 | MIT | https://github.com/vitejs/vite-plugin-react |
| `eslint` | 9.39.5 | MIT | https://github.com/eslint/eslint |
| `eslint-plugin-react-hooks` | 7.1.1 | MIT | https://github.com/facebook/react |
| `eslint-plugin-react-refresh` | 0.5.8 | MIT | https://github.com/ArnaudBarre/eslint-plugin-react-refresh |
| `globals` | 17.14.0 | MIT | https://github.com/sindresorhus/globals |
| `tailwindcss` | 4.3.5 | MIT | https://github.com/tailwindlabs/tailwindcss |
| `typescript` | 5.9.3 | Apache-2.0 | https://github.com/microsoft/TypeScript |
| `typescript-eslint` | 8.74.0 | MIT | https://github.com/typescript-eslint/typescript-eslint |
| `vite` | 8.4.0 | MIT | https://github.com/vitejs/vite |
| `vitest` | 4.1.12 | MIT | https://github.com/vitest-dev/vitest |

Tailwind CSS generates the stylesheet that ships in the bundle. Vite produces the bundle.

Removed relative to upstream: `autoprefixer` (Tailwind CSS 4 applies vendor prefixes itself) and the
direct `postcss` entry (it is still installed as a dependency of `@tailwindcss/postcss` and Vite).

## Fonts, icons and images

The portal ships no font files and requests none: it uses the system font stack. Icons are
inline SVG path data inherited from upstream; the navigation icons appear to come from the
Heroicons outline set (MIT License, Copyright (c) Tailwind Labs, Inc.), which the upstream NOTICE
does not list. No third-party logo is included.
