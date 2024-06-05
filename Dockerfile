# Use the official Node.js image
FROM node:20

# Create and change to the app directory
WORKDIR /usr/src/app

# Copy local code to the container image
COPY . .

# Install dependencies
RUN npm install

# Expose the port your app runs on
EXPOSE 8080

# Set environment variables if needed
ENV PORT=8080

# Run the web service on container startup
CMD ["npm", "start"]
