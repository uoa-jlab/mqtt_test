#!/bin/sh
set -e

# Defaults
WEB_PORT=${WEB_PORT:-5000}
CONFIG_CONSOLE_PORT=${CONFIG_CONSOLE_PORT:-5002}
WORKERS=${GUNICORN_WORKERS:-1}
# For Gevent, 'threads' is not used. We use worker-connections if needed, but default (1000) is usually fine.
# We keep the var for backward compatibility but won't pass it to gevent worker.

echo "[Web] Starting services (Gevent Mode)..."

# 2. Start Main Dashboard - HTTPS :5000
SSL_ARGS=""
if [ "${WEB_SSL_ENABLED:-0}" != "0" ]; then
    if [ -f "$WEB_SSL_CERT" ] && [ -f "$WEB_SSL_KEY" ]; then
        echo "[Web] SSL Enabled. Cert: $WEB_SSL_CERT"
        SSL_ARGS="--certfile $WEB_SSL_CERT --keyfile $WEB_SSL_KEY"
    else
        echo "[Web] SSL Enabled but certificates not found. Falling back to HTTP."
    fi
else
    echo "[Web] SSL Disabled. Running in HTTP mode."
fi

echo "[Web] Starting Main Dashboard on port $WEB_PORT..."
exec gunicorn app:app \
    --bind 0.0.0.0:$WEB_PORT \
    --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    --workers $WORKERS \
    $SSL_ARGS \
    --access-logfile - \
    --error-logfile - \
    --capture-output
