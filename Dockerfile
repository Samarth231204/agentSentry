# AgentGuard: dashboard + Search agent + ADK attack service + CrewAI review service, in one image.
# The project under test is mounted at /project. Keys come from the environment (SSM on AWS).
#
#   docker build -t agentguard .
#   docker run --env-file .env -p 8765:8765 -v "$PWD/../your-project:/project" agentguard
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /usr/local/bin/
ENV PYTHONUNBUFFERED=1 \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_TOOL_DIR=/opt/uv-tools \
    UV_CACHE_DIR=/opt/uv-cache \
    AGENTGUARD_IN_CONTAINER=1

# Semgrep binary for the official Semgrep MCP server.
RUN uv tool install semgrep==1.135.0

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY agentguard ./agentguard
COPY evals ./evals
COPY docs ./docs
RUN uv pip install --system --no-cache .

# Pre-fetch the two external MCP servers (started with uvx at run time) so the first scan does not download them.
RUN uvx --with "pydantic>=2.6,<2.11" semgrep-mcp==0.8.1 --help >/dev/null 2>&1 || true; \
    uvx mcp-server-fetch --help >/dev/null 2>&1 || true

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/a2a', timeout=4)"
CMD ["agentguard", "up", "--project", "/project", "--host", "0.0.0.0", "--port", "8765", "--no-browser"]
