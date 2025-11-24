# Backend Dockerfile - Node 18 (alpine)
FROM node:18-alpine

WORKDIR /app

# install deps
COPY package.json package-lock.json* ./
RUN npm install --production

# copy app
COPY . .

ENV NODE_ENV=production
EXPOSE 5000

# Run migrations and seed (if DB ready) then start server
CMD ["sh","-c","node run_migrations.js || true; node run_seed.js || true; node index.js"]
