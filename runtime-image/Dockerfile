FROM node:22-bookworm-slim

ARG OPENCODE_VERSION=1.17.18

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    openssh-client \
    tar \
  && npm install -g "opencode-ai@${OPENCODE_VERSION}" \
  && npm cache clean --force \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["opencode", "--version"]
