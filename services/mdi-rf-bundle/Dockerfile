FROM node:22-alpine
WORKDIR /app
COPY rf-worker ./rf-worker
COPY voice-worker ./voice-worker
COPY mdi-rf-bundle/runner.mjs ./runner.mjs
CMD ["node","runner.mjs"]