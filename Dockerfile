FROM node:20-alpine

# Install git for repository cloning and analysis
RUN apk add --no-cache git bash curl

WORKDIR /app

# Copy package manifests
COPY package.json ./

# Install all dependencies with legacy peer deps flag to handle tailwindcss/vite/esbuild peer constraints
RUN npm install --legacy-peer-deps

# Copy source code
COPY . .

# Build the frontend bundle
RUN npm run build

# Expose port 3000
EXPOSE 3000

# Set environment to production
ENV NODE_ENV=production
ENV PORT=3000

# Start SandTrace server
CMD ["npm", "start"]
