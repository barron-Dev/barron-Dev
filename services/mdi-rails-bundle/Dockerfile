FROM node:22-alpine
WORKDIR /app
COPY services/a2p-verifier ./a2p
COPY services/chain-indexer ./chain
COPY services/mdi-rails-bundle/runner.mjs ./runner.mjs
CMD ["node","runner.mjs"]