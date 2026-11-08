#!/usr/bin/env bash
# Build step for Render or any similar host.
set -o errexit
pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate --no-input
python manage.py create_admin

# Free hosts reset the SQLite file on every deploy, so recreate the starting users here.
# Set USER_START_PASSWORD (and optionally START_USERNAMES, space separated) in the host's environment.
if [ -n "${USER_START_PASSWORD:-}" ]; then
  python manage.py create_users ${START_USERNAMES:-mukhlis zubair arfeel sultan zeeshan} --password "$USER_START_PASSWORD"
fi
