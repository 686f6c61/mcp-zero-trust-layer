FROM python:3.12-alpine AS build
WORKDIR /site
COPY landing/build.py landing/release.json landing/content.json landing/template.html ./landing/
COPY landing/assets ./landing/assets
COPY landing/fixtures ./landing/fixtures
ARG SITE_URL=""
ARG ENABLE_ANALYTICS="true"
RUN if [ "$ENABLE_ANALYTICS" = "true" ]; then python landing/build.py --production --site-url "$SITE_URL" --analytics; else python landing/build.py --site-url "$SITE_URL"; fi

FROM nginx:alpine
COPY --from=build /site/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
