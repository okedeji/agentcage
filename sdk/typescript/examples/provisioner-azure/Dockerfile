FROM node:22-alpine
WORKDIR /app
COPY package.json tsconfig.json ./
RUN npm install
COPY index.ts .
RUN npx tsc
EXPOSE 8081
CMD ["node", "dist/index.js"]
