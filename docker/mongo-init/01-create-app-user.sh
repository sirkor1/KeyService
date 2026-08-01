#!/bin/sh
set -eu

# Runs only on an empty MongoDB data directory. Credentials are read from the
# container environment and are never embedded in this repository or in JS.
mongosh --quiet \
  --username "$MONGO_INITDB_ROOT_USERNAME" \
  --password "$MONGO_INITDB_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  --eval '
const appDatabase = db.getSiblingDB(process.env.MONGO_INITDB_DATABASE);
appDatabase.createUser({
  user: process.env.MONGO_APP_USERNAME,
  pwd: process.env.MONGO_APP_PASSWORD,
  roles: [{ role: "readWrite", db: process.env.MONGO_INITDB_DATABASE }]
});
'
