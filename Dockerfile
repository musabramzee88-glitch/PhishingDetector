FROM node:20-alpine
WORKDIR /app
COPY package.json server.js make-admin.js index.html admin.html educational-path.js logo.png ./
ENV NODE_ENV=production HOST=0.0.0.0
USER node
EXPOSE 8080
CMD ["node", "server.js"]
