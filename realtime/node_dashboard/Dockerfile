FROM node:20-alpine

WORKDIR /app

# Install dependencies first (cached unless package files change)
COPY package.json package-lock.json ./
RUN npm ci --silent

# Copy application source
COPY public ./public
COPY src ./src

ENV HOST=0.0.0.0
ENV PORT=3000

EXPOSE 3000

CMD ["npm", "start"]
