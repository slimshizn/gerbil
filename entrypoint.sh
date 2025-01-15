#!/bin/sh

set -e

# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
<<<<<<< HEAD
    set -- gerbil "$@"
=======
    set -- newt "$@"
>>>>>>> env-vars
fi

exec "$@"