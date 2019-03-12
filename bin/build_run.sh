#!/usr/bin/env bash

VENV=${1:-"venv"}
CLEAN_DB=${2:-true}
AMDB="manager.db"
ARDB="repository.db"

cd "$(dirname "$0")"
cd ../src

if [ "$CLEAN_DB" = true ]; then
  echo -e "Clean manager and repository databases"
  rm auction_manager/$AMDB
  rm auction_repository/$ARDB
fi 

echo -e "Check for venv $VENV"
if [ ! -d $VENV ]; then
  echo -e "Create venv $VENV"
  python3 -m venv $VENV
  source venv/bin/activate
  pip3 install -r requirements.txt
fi

cd ../bin
echo -e "Start Auction Manager"
x-terminal-emulator -e ./auction_manager.sh $VENV
echo -e "Start Auction Repository"
x-terminal-emulator -e ./auction_repository.sh $VENV
echo -e "Start Client"
x-terminal-emulator -e ./client.sh $VENV
