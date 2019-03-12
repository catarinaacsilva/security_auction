#!/usr/bin/env bash

VENV=${1:-venv}

cd "$(dirname "$0")"
cd ../src
echo -e "Activate virtual environment: $VENV"
source $VENV/bin/activate
echo -e "Execute client"
cd ..
python3 -m src.client.client
