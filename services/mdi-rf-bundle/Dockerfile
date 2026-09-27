FROM node:22-alpine
WORKDIR /app
COPY services/rf-worker ./rf-worker
COPY services/voice-worker ./voice-worker
COPY services/mdi-rf-bundle/runner.mjs ./runner.mjs
CMD ["node","runner.mjs"]