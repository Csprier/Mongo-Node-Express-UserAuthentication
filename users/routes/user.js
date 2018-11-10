const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const User = require('../models/user');

const router = express.Router();

/* =================================================================================== */
// CREATE NEW USER
router.post('/', (req, res, next) => {
	// Check that all required fields are present
	const requiredFields = ['username', 'email', 'password' ];
	const missingField = requiredFields.find(field => !(field in req.body));

	if (missingField) {
		const err = new Error(`Missing ${missingField} in request body`);
		err.status = 422;
		return next(err);
	}

	// Check that all string fields are strings
	const stringFields = ['username', 'email', 'password' ];
	const nonStringField = stringFields.find(field => field in req.body && typeof req.body[field] !== 'string');

	if (nonStringField) {
		const err = new Error(`Field: '${nonStringField}' must be type String`);
		err.status = 422;
		return next(err);
	}

	// Check that fields are trimmed as needed
	const trimmedFields = ['username', 'email', 'password' ];
	const nonTrimmedField = trimmedFields.find(field => req.body[field].trim() !== req.body[field]);

	if (nonTrimmedField) {
		const err = new Error(`Field: '${nonTrimmedField}' cannot start or end with a whitespace!`);
		err.status = 422;
		return next(err);
	}

	// Check that the fields are not just whitespaces
	const whiteSpaceField = requiredFields.find(field => field in req.body && req.body[field].trim().length === 0)
	if (whiteSpaceField) {
		const err = new Error(`Field: '${whiteSpaceField}' must be at least 1 characters long`);
		err.status = 422;
		return next(err);
	}	

	const sizedFields = {
		username: { min: 1 },
		email: { min: 6 },
		password: { min: 8, max: 72 },
	};

	const tooSmall = Object.keys(sizedFields).find(field => {
		if (req.body[field])
			return 'min' in sizedFields[field] && req.body[field].trim().length < sizedFields[field].min;
	});

	const tooLarge = Object.keys(sizedFields).find(field => {
		if (req.body[field])
			return 'max' in sizedFields[field] && req.body[field].trim().length > sizedFields[field].max;
	});

	if (tooSmall) {
		const min = sizedFields[tooSmall].min;
		const err = new Error(`Field: '${tooSmall}' must be at least ${min} characters long`);
		err.status = 422;
		return next(err);
	}

	if (tooLarge) {
		const max = sizedFields[tooLarge].max;
		const err = new Error(`Field: '${tooLarge}' must be at most ${max} characters long`);
		err.status = 422;
		return next(err);
	}

	// Create the new user
	let { username, email, password } = req.body;

	// Check if a username already exists
	User.findOne({ username }, function(err, user) {
		if (user) {
			err = new Error('The username already exists');
			err.status = 400;
			next(err);
		} else {
			return User.hashPassword(password)
			.then(digest => {
				const newUser = {
					username,
					email,
					password: digest
				};
				return User.create(newUser);
			})
			.then(result => {
				return res.status(201)
					.location(`/api/user/${result.id}`)
					.json({ id: result._id, username: result.username, email: result.email });
			})
			.catch(err => {
				if (err.code === 11000) {
					err = new Error('The username already exists');
					err.status = 400;
				}
				next(err);
			});
		}
	});
});

/* =================================================================================== */
// GET ALL USERS
router.get('/', (req, res, next) => {
	User.find()
		.then(user => {
			res.json(user);
		})
		.catch(err => {
			console.error(err);
			next(err);
		});
});

/* =================================================================================== */
// DELETE A USER BY ID - commented out in production
router.delete('/:userId', (req, res, next) => {
	const { userId } = req.params;

	User.findOneAndDelete({ _id: userId })
		.then(() => {
			return res.status(204).json({
				message: 'Deleted user'
			});
		})
		.catch(err => {
			console.error(err);
			next(err);
		});
});

/* =================================================================================== */
// PROTECTED
router.use('/:userId', passport.authenticate('jwt', { session: false, failWithError: true }));

// GET USER BY ID
router.get('/:userId', (req, res, next) => {
	const { userId } = req.params;

	// Valid input check
	if(!mongoose.Types.ObjectId.isValid(userId)) {
		const err = new Error('The `id` is not valid');
		err.status = 400;
		return next(err);
	}

	User.findById({ _id: userId })
		.then(user => {
			if (user) {
				res.json(user);
			} else {
				next();
			}
		})
		.catch(err => {
			console.error(err);
			next(err);
		});
});

/* =================================================================================== */
// PUT ADMIN BY ID
router.put('/:userId', (req, res, next) => {
	const { userId } = req.params;

	/* Valid input check START */
	if (!mongoose.Types.ObjectId.isValid(userId)) {
		const err = new Error('The `id` is not valid');
		err.status = 400;
		return next(err);
	}
	const stringFields = ['username', 'password', 'email'];
	const nonStringField = stringFields.find(field => {
		return field in req.body && typeof req.body[field] !== 'string';
	});

	if (nonStringField) {
		const err = new Error(`Field: '${nonStringField}' must be typeof String`);
		err.status = 422;
		return next(err);
	}
	const trimmedFields = ['username', 'password', 'email'];
	const nonTrimmedField = trimmedFields.find(field => {
		if(req.body[field]){
			return field in req.body && req.body[field].trim() !== req.body[field];
		}
	});

	if (nonTrimmedField) {
		const err = new Error(`Field: '${nonTrimmedField}' cannot start or end with a whitespace!`);
		err.status = 422;
		return next(err);
	}

	const sizedFields = {
		username: { min: 1 },
		email: { min: 6 },
		password: { min: 8, max: 72 },
	};

	const tooSmall = Object.keys(sizedFields).find(field => {
		if(req.body[field]) {
			return 'min' in sizedFields[field] && req.body[field].trim().length < sizedFields[field].min;
		}
	});

	const tooLarge = Object.keys(sizedFields).find(field => {
		if(req.body[field])
			return 'max' in sizedFields[field] && req.body[field].trim().length > sizedFields[field].max;
	});

	if (tooSmall) {
		const min = sizedFields[tooSmall].min;
		const err = new Error(`Field: '${tooSmall}' must be at least ${min} characters long`);
		err.status = 422;
		return next(err);
	}

	if (tooLarge) {
		const max = sizedFields[tooLarge].max;
		const err = new Error(`Field: '${tooLarge}' must be at most ${max} characters long `);
		err.status = 422;
		return next(err);
	}
	/* Valid input check END */

	let { password } = req.body;

	return User.hashPassword(password)
		.then(digest => {
			const user = {
				...req.body,
				password: digest
			};
			return User.findByIdAndUpdate(userId, user, { new:true });
		})
		.then(user => {
			if (user) {
				res.json(user);
			} else {
				next();
			}
		})
		.catch(err => {
			if (err.code === 11000) {
				err = new Error('Email already exists');
				err.status = 400;
			}
			next(err);
		});
});

module.exports = router;