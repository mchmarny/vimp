FROM node:latest
WORKDIR /src/
COPY . /src/
RUN npm install --only=production
CMD ["node", "index.js"]
