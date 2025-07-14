# Base image
FROM node:24-alpine

    # Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the code
COPY . .

# Expose the port your app runs on
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
