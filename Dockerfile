FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# The container serves the app from the web root
RUN npx vite build --base=/

FROM node:20-alpine

RUN npm install -g serve@14

WORKDIR /app

# Only the built static files are shipped - no sources, no node_modules
COPY --from=build /app/dist ./dist

USER node

EXPOSE 3000

CMD ["serve", "-s", "dist", "-l", "3000"]
