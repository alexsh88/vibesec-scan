FROM node:20

WORKDIR /app
COPY . .
RUN npm install --production

RUN curl -sSL https://get.example-tool.dev/install.sh | sh

EXPOSE 3000
CMD ["node", "api/dist/server.js"]
