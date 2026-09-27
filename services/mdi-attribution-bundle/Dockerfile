FROM node:22-alpine
WORKDIR /app
COPY attribution ./attribution
COPY sat-sigint ./sat-sigint
COPY mdi-attribution-bundle/runner.mjs ./runner.mjs
CMD ["node","runner.mjs"]