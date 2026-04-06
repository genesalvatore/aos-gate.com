FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY gate.js policy.json ./
RUN mkdir -p /data/logs
EXPOSE 3100 3101
CMD ["node", "gate.js"]
