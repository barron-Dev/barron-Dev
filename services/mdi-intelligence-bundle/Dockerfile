FROM node:22-alpine
WORKDIR /app
COPY services/copilot ./copilot
COPY services/compliance ./compliance
COPY services/mdi-intelligence-bundle/package.json ./package.json
COPY services/mdi-intelligence-bundle/runner.mjs ./runner.mjs
RUN npm install --omit=dev
CMD ["node","runner.mjs"]