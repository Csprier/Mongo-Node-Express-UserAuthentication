const mongoose = require('mongoose');
const { MONGODB_URI } = require('../config');
const seedUsers = require('../db/seed/users');

mongoose.connect(MONGODB_URI, { useNewUrlParser: true })
  .then(() => mongoose.connection.db.dropDatabase())
  .then(() => {
    return Promise.all(seedUsers.map( user => User.hashPassword(user.password)));
  })
  .then( digests => {
    seedUsers.forEach((user, i) => user.password = digests[i]);

    return Promise.all([
      User.insertMany(seedUsers),
      User.createIndexes(),
    ]);
  })
  .then(() => mongoose.disconnect())
  .catch(err => {
    console.error(`ERROR: ${err.message}`);
    console.error(err);
  });