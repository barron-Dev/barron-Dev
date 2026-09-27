FROM node:22-alpine
WORKDIR /app
COPY copilot ./copilot
COPY compliance ./compliance
COPY mdi-intelligence-bundle/package.json ./package.json
COPY mdi-intelligence-bundle/runner.mjs ./runner.mjs
RUN npm install --omit=dev
CMD ["node","runner.mjs"]