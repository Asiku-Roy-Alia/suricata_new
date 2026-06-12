FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY public ./public
COPY src ./src
ENV HOST=0.0.0.0
ENV PORT=3000
CMD ["npm", "start"]
