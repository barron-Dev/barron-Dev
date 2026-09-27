FROM node:22-alpine
WORKDIR /app
COPY services/attribution ./attribution
COPY services/sat-sigint ./sat-sigint
COPY services/mdi-attribution-bundle/runner.mjs ./runner.mjs
CMD ["node","runner.mjs"]