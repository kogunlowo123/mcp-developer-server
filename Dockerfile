# syntax=docker/dockerfile:1.9
# Multi-stage build: dependencies are resolved from the lockfile in a builder
# stage, and only the virtual environment plus application source are copied
# into a slim runtime image that executes as a non-root user.

ARG PYTHON_VERSION=3.12
ARG UV_VERSION=0.10.10

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

# UV_PROJECT_ENVIRONMENT, not just VIRTUAL_ENV: uv resolves the project
# environment from the former. Without it `uv sync` installs into /build/.venv,
# and the image ships an empty /opt/venv that starts and then fails on the
# first import.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    VIRTUAL_ENV=/opt/venv \
    UV_PROJECT_ENVIRONMENT=/opt/venv

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /build

# Dependencies first so the layer is reused whenever only source changes.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv "${VIRTUAL_ENV}" \
 && uv sync --locked --no-dev --no-install-project

COPY src ./src
# --no-editable: uv installs a workspace project in editable mode by default,
# leaving a .pth that points at /build/src — a path the runtime stage does not
# have.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:${PATH}" \
    VIRTUAL_ENV=/opt/venv

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 10001 app; \
    useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app; \
    install -d -o app -g app /app /app/var

COPY --from=builder --chown=app:app /opt/venv /opt/venv
COPY --from=builder --chown=app:app /build/src /app/src

WORKDIR /app
USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

ENTRYPOINT ["python", "-m"]
