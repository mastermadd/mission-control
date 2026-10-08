FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build && npm test
FROM node:24-bookworm-slim
WORKDIR /app
COPY --from=build /app/package.json /app/api.js /app/server.mjs /app/db.mjs /app/auth.mjs /app/runtime.js /app/provision.mjs ./
COPY --from=build /app/lib ./lib
COPY --from=build /app/public ./public
COPY --from=build /app/migrations ./migrations
RUN find /app -type d -exec chmod 0755 {} + \
 && find /app -type f -exec chmod 0644 {} + \
 && mkdir /data /config && chown node:node /data /config
USER node
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node","server.mjs"]
