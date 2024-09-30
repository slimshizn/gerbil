#!/bin/sh

# Sample from https://github.com/traefik/traefik-library-image/blob/5070edb25b03cca6802d75d5037576c840f73fdd/v3.1/alpine/entrypoint.sh

set -e

# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
    set -- gerbil "$@"
fi

# if our command is a valid Gerbil subcommand, let's invoke it through Gerbil instead
# (this allows for "docker run gerbil version", etc)
if gerbil "$1" --help >/dev/null 2>&1
then
    set -- gerbil "$@"
else
    echo "= '$1' is not a Gerbil command: assuming shell execution." 1>&2
fi

exec "$@"