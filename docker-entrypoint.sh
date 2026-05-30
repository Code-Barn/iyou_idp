#!/bin/sh
set -e

echo "Executing Database Migrations..."
python manage.py migrate --noinput

echo "Spawning Gunicorn Web Server Application Engine on Core Port 8000..."
exec gunicorn config.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --timeout 120 \
    --access-logfile -
