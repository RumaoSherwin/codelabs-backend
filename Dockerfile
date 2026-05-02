FROM node:20-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    default-jdk-headless \
    g++ \
    gcc \
    golang-go \
    mono-mcs \
    mono-runtime \
    python3 \
    rustc \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY server.js ./

USER node
EXPOSE 3000

CMD ["npm", "start"]
