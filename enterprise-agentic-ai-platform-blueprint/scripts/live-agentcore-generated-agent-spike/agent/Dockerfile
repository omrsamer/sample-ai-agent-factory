# syntax=docker/dockerfile:1
#
# ARM64, non-root container image for the real generated-agent reference.
#
# Unlike the inert compatibility handler, this image installs the Strands +
# LiteLLM + MCP clients and runs an agent that actually calls the platform LLM
# Gateway (LiteLLMModel), the platform Tools Gateway (MCPClient), and AgentCore
# Memory. It listens on :8080 and exposes the /invocations and /ping contract
# that BedrockAgentCoreApp implements. No credentials are baked in — the Gateway
# bearer token is provided at runtime via AgentCore Identity M2M — and it runs
# as an unprivileged user. Network egress is governed by the Runtime's
# networkConfiguration at deploy time, not by this image.
#
# The AWS-maintained AL2023 Python ARM64 base is pinned, with system packages
# updated during the build. The final image must be rebuilt from the exact
# product revision and scanned to zero Critical/High findings before any
# Runtime consumes it by digest.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# AWS-maintained AL2023 Python base, pinned to the live-scanned ARM64 digest.
FROM public.ecr.aws/lambda/python:3.13@sha256:50ce57123df27aa4eee37bea58b85707833ae16fdcd0a75d9641375d6b96ad52

# AL2023 repository versions are pinned independently of the container tag.
# This released repository includes the vendor RPM fixes in ALAS2023-2026-3430.
RUN dnf upgrade -y --releasever 2023.12.20261112 && dnf clean all

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install exact-pinned runtime dependencies first for layer caching.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt \
    && pip check

# Copy only the agent entrypoint.
COPY agent.py /app/agent.py

# Drop to a numeric, unprivileged user.
USER 10001

# AgentCore Runtime speaks HTTP to the container on 8080.
EXPOSE 8080

ENTRYPOINT ["python", "-u", "agent.py"]
CMD []
