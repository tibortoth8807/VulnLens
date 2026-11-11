# Build stage
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
# Switch to "npm ci" once package-lock.json is committed.
RUN npm install
COPY . .
RUN npm run build

# Runtime stage
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
