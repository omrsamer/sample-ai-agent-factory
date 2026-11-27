# Agent Factory Portal applications

The two applications behind the opt-in portal stages. What the portal is, the
rules it keeps and how to deploy it are in
[`docs/AGENT_FACTORY_PORTAL.md`](../../docs/AGENT_FACTORY_PORTAL.md).

| Directory | What it is | Licence |
| --- | --- | --- |
| [`api/`](api/README.md) | Read-only API (Python, FastAPI on AWS Lambda). Reads the Platform Registry and each cell through its fleet reader role. `IAM_ACTIONS.md` lists every action it calls; the infrastructure grants exactly those. | MIT-0 |
| [`web/`](web/README.md) | Web application (React, Vite). Loads `config.json` at start, signs in with Amazon Cognito or Microsoft Entra ID, and issues only `GET` requests. `API_CONTRACT.md` lists every endpoint it calls. | Apache-2.0 for files derived from the Agentic Governance Platform, MIT-0 for the rest; see `NOTICE` and `THIRD_PARTY.md` |

## Build

Both bundles are built before `cdk synth` or `cdk deploy` of the
`agent-factory-portal` stage; the stage fails with a hint when one is missing.

```bash
(cd api && ./build.sh)                       # -> api/dist  (Python 3.13, arm64)
(cd web && npm ci && npm run build)          # -> web/dist
```

## Test

```bash
(cd api && python3 -m pip install -r requirements-dev.txt && python3 -m pytest -q)
(cd web && npm ci && npx tsc -b && npx eslint . && npx vitest run)
```

Infrastructure conformance: `npx jest tests/conformance/phase-27-agent-factory-portal.test.ts`.
Live checks against a deployed portal: `tests/integration/test_agent_factory_portal.py`.
