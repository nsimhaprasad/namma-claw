FROM node:22-bookworm

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Clone OpenClaw from GitHub
RUN git clone --depth 1 https://github.com/openclaw/openclaw.git . && \
    pnpm install && \
    pnpm ui:build && \
    pnpm build

# Run as non-root user node (uid 1000)
USER node

# Start gateway server
CMD ["node", "dist/index.js", "gateway", "--allow-unconfigured", "--bind", "lan", "--port", "18789"]
