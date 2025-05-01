FROM node:22-alpine

WORKDIR /app

# Install dependencies first (better layer caching)
COPY package*.json ./
RUN npm ci --only=production

# Copy only necessary files
COPY server.js .
COPY auth/ ./auth/
COPY public/ ./public/

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

USER appuser

# Use init to handle signals properly
CMD ["node", "server.js"] 