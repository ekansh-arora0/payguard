FROM nginx:1.25-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our config
COPY nginx.conf /etc/nginx/nginx.conf

# Create cert directory
RUN mkdir -p /etc/nginx/certs

EXPOSE 80 443
