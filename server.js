require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const morgan = require('morgan');
const passport = require('passport');

const localStrategy = require('./auth/local');
const jwtStrategy = require('./auth/jwt');

const { PORT, CLIENT_ORIGIN, MONGODB_URI } = require('./config');
const { dbConnect } = require('./db-mongoose');

// ROUTERS
const authRouter = require('./users/routes/auth');
const userRouter = require('./users/routes/user');

// Instantiate express instance
const app = express();

// Morgan
app.use(
	morgan(process.env.NODE_ENV === 'production' ? 'common' : 'dev', {
		skip: (req, res) => process.env.NODE_ENV === 'test'
	})
);

// CORS
// ===============================================================================================
app.use(
  cors({ origin: CLIENT_ORIGIN })
);
app.use(function(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Access-Control-Allow-Headers, Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, X-Access-Token, XKey, Authorization');
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});
app.options('*', cors());

// ===============================================================================================
// Parse request body
app.use(express.json());

// ===============================================================================================
// Utilize the given `strategy`
passport.use(localStrategy);
passport.use(jwtStrategy);

// Endpoints
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

// Query to test connection of the http server
app.get('/', function (req, res) {
  res.send('hello world');
});

// Catch-all Error handler; Added NODE_ENV check to prevent stacktrace leak
app.use(function (err, req, res, next) {
	res.status(err.status || 500);
	res.json({
		message: err.message,
		error: app.get('env') === 'development' ? err : {}
	});
});

// ===============================================================================================
// Listen for incoming connections
if (require.main === module) {
  const options = {
    useNewUrlParser: true
  }
  
  mongoose.connect(MONGODB_URI, options)
    .then(instance => {
      const conn = instance.connections[0];
      console.info(`Connected to: mongodb://${conn.host}:${conn.port}/${conn.name}`);
    })
    .catch(err => {
      console.error(`ERROR: ${err.message}`);
      console.error('\n === Did you remember to start `mongod`? === \n');
      console.error(err);
		});

	app.listen(PORT, () => {
		console.info(`Server listening on ${PORT}!`);
	})
	.on('error', err => {
		console.error('Express failed to start');
		console.error(err);
	});
}

module.exports = app;