#!/bin/bash
set -e

# config file for runtime env variables for frontend
CONFIG_FILE="/opt/app-root/src/config.js"

# fallback
TARGET_API_URL=${API_URL:-"http://localhost:8080"}

echo "Running with TARGET_API_URL=${TARGET_API_URL}"

# rewriting the whole config file
cat > $CONFIG_FILE << EOL
window._env_ = {
  API_URL: '${TARGET_API_URL}'
};
EOL

echo "Setting API_URL to ${TARGET_API_URL} in ${CONFIG_FILE}"

exec nginx -g 'daemon off;'
