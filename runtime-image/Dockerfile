ARG NODE_BASE_IMAGE
FROM ${NODE_BASE_IMAGE}

ARG OPENCODE_VERSION=1.18.8
ARG NPM_VERSION=11.18.0
# npm vendors these two and still ships versions with published denial-of-service
# advisories, so the fixed releases are installed over the vendored copies. Both are
# pinned by exact version and verified below; drop an entry once npm vendors it.
ARG NPM_VENDORED_BRACE_EXPANSION_VERSION=5.0.9
ARG NPM_VENDORED_IP_ADDRESS_VERSION=10.3.1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    build-essential \
    git \
    openssh-client \
    tar \
  && npm install -g "npm@${NPM_VERSION}" \
  && npm install -g --allow-scripts=opencode-ai "opencode-ai@${OPENCODE_VERSION}" \
  && npm install --prefix /tmp/npm-vendored-patch --no-save --ignore-scripts \
    "brace-expansion@${NPM_VENDORED_BRACE_EXPANSION_VERSION}" \
    "ip-address@${NPM_VENDORED_IP_ADDRESS_VERSION}" \
  && for pkg in brace-expansion ip-address; do \
       src="/tmp/npm-vendored-patch/node_modules/$pkg"; \
       test -f "$src/package.json" || exit 1; \
       find /usr/local/lib/node_modules/npm/node_modules -type d -name "$pkg" -prune -print \
         | while read -r target; do rm -rf "$target" && cp -R "$src" "$target"; done; \
     done \
  && rm -rf /tmp/npm-vendored-patch \
  && node -e "const {execFileSync}=require('node:child_process');const fs=require('node:fs');const expected={'brace-expansion':'${NPM_VENDORED_BRACE_EXPANSION_VERSION}','ip-address':'${NPM_VENDORED_IP_ADDRESS_VERSION}'};const root='/usr/local/lib/node_modules/npm/node_modules';for(const [name,version] of Object.entries(expected)){const found=execFileSync('find',[root,'-type','d','-name',name,'-prune','-print'],{encoding:'utf8'}).split('\n').filter(Boolean);if(found.length===0)continue;for(const dir of found){const actual=JSON.parse(fs.readFileSync(dir+'/package.json','utf8')).version;if(actual!==version)throw new Error('unpatched '+name+'@'+actual+' at '+dir);}}" \
  && npm --version \
  && npm cache clean --force \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /baseline /run/openchamber-workspace \
  && chown -R node:node /workspace /baseline /run/openchamber-workspace

USER node
WORKDIR /workspace

CMD ["opencode", "--version"]
