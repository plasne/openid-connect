FROM node
WORKDIR /app
COPY package.json package.json
COPY package-lock.json package-lock.json
COPY index.js index.js
COPY www www
RUN npm install
ENTRYPOINT ["node", "index.js"]