FROM node:22-alpine
WORKDIR /app
COPY a2p-verifier ./a2p
COPY chain-indexer ./chain
COPY mdi-rails-bundle/runner.mjs ./runner.mjs
CMD ["node","runner.mjs"]