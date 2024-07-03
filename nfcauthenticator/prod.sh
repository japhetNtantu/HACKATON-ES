#!/bin/bash
set -e

if [ -z "$DJANGO_STATIC_ROOT" ]; then
  export DJANGO_STATIC_ROOT="/var/wwww/static"
fi

if [ -z "$DJANGO_MEDIA_ROOT" ]; then
  export DJANGO_MEDIA_ROOT="/var/wwww/media"
fi

if [ -z "$FRONT_HOST" ]; then
  export FRONT_HOST="http://127.0.0.1:8081"
fi

if [ -z "$FRONTEND_URL" ]; then
  export FRONTEND_URL="${FRONT_HOST}/#/reset/password/"
fi

if [ -z "$POSTGRES_DATA" ]; then
  export POSTGRES_DATA="/var/lib/postgresql/data/"
fi


while ! PGPASSWORD=${PGPASS} psql -h ${POSTGRES_HOST} -U postgres -c '\q'; do echo "En attente du demarrage de postgresql..." && sleep 1; done
if ! PGPASSWORD=${PGPASS}  psql -U postgres -h ${POSTGRES_HOST} -p ${POSTGRES_PORT} -lqt | cut -d \| -f 1 | cut -d ' ' -f 2 | grep -q "^ekila_db$"; then
    PGPASSWORD=${PGPASS} createdb -U postgres -h ${POSTGRES_HOST} -p ${POSTGRES_PORT} estiam_db
else
    echo "La database existe déjà..."
fi

mkdir -p ${DJANGO_STATIC_ROOT} && chown root:www-data ${DJANGO_STATIC_ROOT}
mkdir -p ${DJANGO_MEDIA_ROOT} && chown root:www-data ${DJANGO_MEDIA_ROOT}
mkdir -p ${POSTGRES_DATA} && chown root:www-data ${POSTGRES_DATA}

make wait_db
make migrate
make collectstatic

USER_EXISTS="from django.contrib.auth import get_user_model; User = get_user_model(); exit(User.objects.exists())"
python manage.py shell -c "$USER_EXISTS" && python manage.py createsuperuser --username admin --email admin@gmail.com --noinput
exec gosu estiamadm daphne -b 0.0.0.0 -p ${DJANGO_DEV_SERVER_PORT} nfcauthenticator.asgi:application
exec "$@"
