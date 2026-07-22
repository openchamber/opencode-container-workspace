ARG NODE_BASE_IMAGE
FROM ${NODE_BASE_IMAGE}

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin gateway

COPY --chown=root:root src/egress-gateway.js /app/gateway.mjs

USER 10001:10001
EXPOSE 3128
ENTRYPOINT ["node", "/app/gateway.mjs"]
