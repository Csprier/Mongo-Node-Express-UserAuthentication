const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');

// SCHEMA
const User = require('../models/user');

const { JWT_SECRET, JWT_EXPIRY } = require('../../config');
const router = express.Router();

const localAuth = passport.authenticate('local', { session: false, failWithError: true });

// Login endpoint for login
router.post('/login', localAuth, (req, res) => {
	const authToken = createAuthToken(req.user);
	return res.status(200).json({ authToken });
});

// Refresh AuthToken
router.use('/refresh', passport.authenticate('jwt', { session: false, failWithError: true }));

router.post('/refresh', (req, res, next) => {
	User.find({ id: req.user.id })
  .then(user => {
    const authToken = createAuthToken(user[0]);
    res.json({ authToken });
  })
  .catch(err => {
    console.error(err);
    next(err);
  });
});

// Generate AuthToken for user
const createAuthToken = (user) => {
	return jwt.sign({ user }, JWT_SECRET, {
		subject: user.username,
		expiresIn: JWT_EXPIRY
	});
};

module.exports = router;