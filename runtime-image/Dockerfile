ARG NODE_BASE_IMAGE
FROM ${NODE_BASE_IMAGE}

ARG OPENCODE_VERSION=1.18.4

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    git \
    openssh-client \
    tar \
  && npm install -g "opencode-ai@${OPENCODE_VERSION}" \
  && npm cache clean --force \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /baseline /run/openchamber-workspace \
  && chown -R node:node /workspace /baseline /run/openchamber-workspace

USER node
WORKDIR /workspace

CMD ["opencode", "--version"]
