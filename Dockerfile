FROM node:22-alpine

WORKDIR /app

# Install production dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy application source, policy, and constitutional governance skill
COPY gate.js policy.json ./
COPY skill/ ./skill/

# Provision log volume directory and set non-root ownership
RUN mkdir -p /data/logs && chown -R node:node /app /data

# Switch to unprivileged node user
USER node

# Healthcheck monitoring the proxy health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3100/health || exit 1

EXPOSE 3100 3101

CMD ["node", "gate.js"]
