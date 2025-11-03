#!/bin/bash
set -e

# This is the path where Nginx serves files from
# The default root in the base image is /opt/app-root/src
CONFIG_FILE="/opt/app-root/src/config.js"

# fallback
# Use the API_URL from the environment, or use the default if it's not set
TARGET_API_URL=${API_URL:-"http://localhost:8080"}

echo "Running with TARGET_API_URL=${TARGET_API_URL}"
echo "Generating ${CONFIG_FILE}..."

# Write the config file from scratch to match your app's format
cat > $CONFIG_FILE << EOL
window._env_ = {
  API_URL: '${TARGET_API_URL}'
};
EOL

echo "Setting API_URL to ${TARGET_API_URL} in ${CONFIG_FILE}"
echo "Configuration complete. Starting Nginx..."

# Start Nginx in the foreground
exec nginx -g 'daemon off;'
