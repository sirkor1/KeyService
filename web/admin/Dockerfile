FROM node:22-alpine AS build
WORKDIR /app

# Слой зависимостей отдельно: пересобирается только при изменении манифестов.
COPY web/admin/package.json web/admin/package-lock.json* ./
RUN npm ci

COPY web/admin/ ./
RUN npm run lint && npm run build

FROM nginx:1.27-alpine AS runtime
COPY web/admin/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
