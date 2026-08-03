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
const appUser = {
  user: process.env.MONGO_APP_USERNAME,
  pwd: process.env.MONGO_APP_PASSWORD,
  roles: [{ role: "readWrite", db: process.env.MONGO_INITDB_DATABASE }]
};

// The image entrypoint creates the root user before it sources this hook. If
// an interrupted fresh bootstrap is resumed, this makes rerunning the hook a
// narrow repair of the application account without touching application data.
if (appDatabase.getUser(appUser.user)) {
  appDatabase.updateUser(appUser.user, { pwd: appUser.pwd, roles: appUser.roles });
} else {
  appDatabase.createUser(appUser);
}
'
