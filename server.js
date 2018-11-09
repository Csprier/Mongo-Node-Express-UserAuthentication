require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const passport = require('passport');

const localStrategy = require('./auth/local');
const jwtStrategy = require('./auth/jwt');

const { PORT, CLIENT_ORIGIN } = require('./config');
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
app.use(cors({ origin: CLIENT_ORIGIN }));

// Parse request body
app.use(express.json());

// Auth
passport.use(localStrategy);
passport.use(jwtStrategy);

// Endpoints
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

// Catch-all Error handler
// Add NODE_ENV check to prevent stacktrace leak
app.use(function (err, req, res, next) {
	res.status(err.status || 500);
	res.json({
		message: err.message,
		error: app.get('env') === 'development' ? err : {}
	});
});

// RUN SERVER FUNCTION
function runServer(port = PORT) {
	const server = app
		.listen(port, () => {
			console.info(`App listening on port ${server.address().port}`);
		})
		.on('error', err => {
			console.error('Express failed to start');
			console.error(err);
		});
}

if (require.main === module) {
	dbConnect();
	runServer();
}

module.exports = { app };