# Mongo-Node-Express-UserAuthentication

User Authentication using MongoDB, Express and NodeJS.

First, we'll make a directory to house our server. I'm on macOS, so all the commands seen in this guide will be tailored to that. So, open up your terminal and enter these commands! :D

`$ cd ~/Desktop`

`$ mkdir programName-server`

`$ npm init`

These commands will move you to your Desktop, make a folder for your server, and set you up to create your package.json file skeleton. After filling out the prompts, it's time to install our dependencies. 

You can do this individually, or in one ridiculously long command, and a slightly shorter one for the devDependencies. 

`$ npm install bcryptjs cors dotenv express jsonwebtoken mongoose morgan nodemon passport passport-jwt passport-local`

`$ npm install mocha chai chai-http cross-env --save-dev`

 Alteratively, copy/paste the following and enter in `npm install`.
```
"dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^6.1.0",
    "express": "^4.16.4",
    "jsonwebtoken": "^8.3.0",
    "mongoose": "^5.3.10",
    "morgan": "^1.9.1",
    "nodemon": "^1.18.6",
    "passport": "^0.4.0",
    "passport-jwt": "^4.0.0",
    "passport-local": "^1.0.0"
  },
  "devDependencies": {
    "chai": "^4.2.0",
    "chai-http": "^4.2.0",
    "cross-env": "^5.2.0",
    "mocha": "^5.2.0"
  }
  ```


Now that we have our package.json file in order and our node_modules folder is created, let's create our `server.js` file. This is the entry point of our app, so we'll need to modify the "main" section of the package.json to reflect this; or, if you're lazy, name `server.js` as `index.js` and leave your package.json alone(it is defaulted as index.js). I like to rename it for naming-convention's sake.

Now that we have our server file in order, we need to require in our dependencies.
```
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const passport = require('passport');
```

We use `require('dotenv').config()` to cast some magic to help us with our environment variables. (I will elaborate on this at a later time).


Alright, we're looking good so far! Next, will instantiate an express instance, set up our logger, cors, and body parser.
```
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
```


Alright, now for a little bit of error handling. In the lines under what we just wrote, add this snippet:
```
// Catch-all Error handler
// Add NODE_ENV check to prevent stacktrace leak
app.use(function (err, req, res, next) {
	res.status(err.status || 500);
	res.json({
	message: err.message,
	error: app.get('env') === 'development' ? err : {}
    });
});
```

Finally, we'll setup the function to actually run the server. There's still more configuration required before we can do that, but let's get this in the file, so we can get to just that! :D
```
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

module.exports = { app }; // Last line of the file
```

User Model and Routes

Alright, now it's time to finish configuring. What we're going to do next is set up our User model(the schema) and the endpoints which will allow us to create, login, and authenticate a user.

From our root directory of our server, let's create some folders:

`$ mkdir users`
`$ cd users`
`$ mkdir models`
`$ mkdir routes`
`$ cd models && touch user.js`
`$ cd ../routes && touch user.js && touch auth.js`
`$ cd ../`

Okay, that's a fair bit of terminal voodoo, so let's recap! Starting in our root directory, we make a directory users. Next we change into the directory we just made and make two new directories; models and routes. Then, we change into the models directory and create a file, user.js. After that, with a trickier command, we change directories by going back up one level in our tree and then into the routes directory. Followed by creating two files; user and auth.js. Then, for good measure, as to not forget later, we change back to the root directory. 

After all this, our file tree should look like this: (Not counting node_modules and other files)
```
programName-server
|
|_users
|     |_models
|     |      |_user.js
|     |
|     |_routes
|            |_ auth.js
|            |_user.js
|_server.js
```

Okay, now we're ready to edit the files we just created! :D

Open up the `models/user.js` and we'll add the following:
```
// import dependencies
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// define our schema
const userSchema = new mongoose.Schema({
    username: { type: String },
    email: { type: String },
    password: { type: String, require: true },
}, { timestamps: true });

// modify our schema
userSchema.set('toObject', {
    transform: (doc, ret) => {
        ret.id = ret._id;
        delete ret._id;
        delete ret.__v;
        delete ret.password;
    }
});

// 
userSchema.methods.validatePassword = function(password) {
    return bcrypt.compare(password, this.password);
};

userSchema.statics.hashPassword = function (password) {
    return bcrypt.hash(password, 10);
};

module.exports = mongoose.model('User', userSchema);
```


Now that the User schema is created, we're going to set up our endpoints. We'll start with the POST request to create a user. Open up our `user/routes/user.js` and import our dependencies.
```
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const User = require('../models/user');

const router = express.Router();
```

Below them, we'll write up our beast of an endpoint. 
```
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
        const err = new Error(`Field: '${nonStringField}' must be typeof String`);
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
        const err = new Error(`Field: '${tooLarge}' must be at most ${max} characters long `);
        err.status = 422;
        return next(err);
    }

    // Create the new user
    let { username, email, password } = req.body;

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
                .json(result);
        })
        .catch(err => {
            if (err.code === 11000) {
                err = new Error('The email already exists');
                err.status = 400;
            }
        next(err);
    });
});
```

OooEeee! That's a hefty endpoint at first glance. Let's break it down so we can better understand all the validation taking place.
When we create a new user, we register is with three fields. Username, Email, and password.
First we check if any of these fields are missing; no user can register without all the fields.
Second we check that all string fields are strings, anything else is invalid.
Third we check that fields are trimmed as needed, so there are no extra white-spaces.
Then we'll check to make sure the given fields are valid lengths; not to small, not too large.
Then finally, we create our new User and modify the password to be the newly hashed version of the password. With that result, if everything was successful, we'll send a 201 status; and if the email was already used, we'll catch that and send an error.


That should work. You can check in postman, but if it shouldn't work, don't fret, by the end of this, everything will work. :D You'll need to start your mongo server and nodemon server.js in your terminal to make this possible.

Alright, so... next we'll open up our `user/routes/auth.js` file.

Import our dependencies, schema, and instantiate a router at the top of the file. Dont worry about the JWT_SECRET, we'll cover that in this section too. For now, just have that line in there anyway.
```
const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');

// SCHEMA
const User = require('../models/user');

const { JWT_SECRET, JWT_EXPIRY } = require('../../config');
const router = express.Router();
```

Okay, time for the endpoints.
```
const localAuth = passport.authenticate('local', { session: false, failWithError: true });

// Login endpoint for login
router.post('/login', localAuth, (req, res) => {
    const authToken = createAuthToken(req.user);
    return res.json({ authToken });
});

// Refresh AuthToken
router.use('/refresh', passport.authenticate('jwt', { session: false, failWithError: true }));

router.post('/refresh', (req, res, next) => {
    User.find({ _id: req.user.id })
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

module.exports = router; // Last line of the file
```

So, what's happening here?  We have our endpoints setup for logging in as a user and refreshing the JWT token. This is important for getting the JWT for the user, so we can keep things like their data protected. Finally, we have a function to generate the auth token. Our authentication is almost complete! Mwahaha! *lightning cracks in the sky above* - *clears throat*. 

Let's navigate back to our root directory for a moment and create a `config.js` file. After that, we're going to create a folder in the same root directory; let's call it 'auth', and inside that folder we'll create two files: `jwt.js` and `local.js`. So, now our file tree should look like this:
```
programName-server
|
|_auth
|    |_jwt.js
|    |_local.js
|
|_users
|     |_models
|     |     |_user.js
|     |
|     |_routes
|           |_ auth.js
|           |_user.js
|_config.js
|_server.js
```
Now we're ready to finalize our authentication, give or take a few added steps we'll make up for later. So! Here we go!

Open up `~/auth/jwt.js` and add this code:
```
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { JWT_SECRET } = require('../config');

const options = {
    secretOrKey: JWT_SECRET,
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    algorithms: ['HS256']
};


const jwtStrategy = new JwtStrategy(options, (payload, done) => {
    done(null, payload.user);
});

module.exports = jwtStrategy; // Last line of the file
```
We import our dependencies at the top, create an options object, and create our strategy before exporting it! :D


Now open up `~/auth/local.js` and add this code:
```
const { Strategy: LocalStrategy } = require('passport-local');
const User = require('../users/models/user');

const localStrategy = new LocalStrategy((username, password, done) => {
    let user;
    User.find({username})
        .then(results => {
            user = results[0];
            if (!user) {
                return Promise.reject({
                    reason: 'LoginError',
                    message: 'Incorrect username',
                    location: 'username'
            });
        }
        return user.validatePassword(password);
    })
    .then(isValid => {
        if (!isValid) {
            return Promise.reject({
                reason: 'LoginError',
                message: 'Incorrect password',
                location: 'password'
            });
        }
        return done(null, user);
    })
    .catch(err => {
        if (err.reason === 'LoginError') {
            return done(null, false);
        }
        return done(err);
    });
});

module.exports = localStrategy; // Last line of the file
```

Alright, that's a lot of voodoo to spin up. We're almost done, though! Stay strong! 
Let's open up our `~/config.js` file. We're going to export quite a few things here, check it out:
```
module.exports = {
    PORT: process.env.PORT || 8080,
    CLIENT_ORIGIN: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
    DATABASE_URL: process.env.DATABASE_URL || 'mongodb://localhost/programName',
    TEST_DATABASE_URL: process.env.TEST_DATABASE_URL || 'mongodb://localhost/programName',
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRY: process.env.JWT_EXPIRY || '7d'
};
```
You'll need to modify the localhost programNames accordingly but other than that, that's all we are adding in this file.


Okay, my friends, that is all of the heavy lifting. Now we just have to account for a few more things and we'll be ready to go with fully functional User Authentication! Are you excited?! You should be, this is fancy stuff.
So, next we need to account for some version control. We don't want our `.env` file that we'll create to be shown in your repository, among other files.
Let's create a few more files: `./.env`, `./db-mongoose`, and `./gitignore`.

Now, our file tree should look like this:
```
programName-server
|
|_ auth
|     |_ jwt.js
|     |_ local.js
|
|_ users
|     |_ models
|     |       |_ user.js
|     |
|     |_ routes
|             |_  auth.js
|             |_ user.js
|_ config.js
|_ .env
|_ .gitignore
|_ db-mongoose.js
|_ server.js
```

Alright, let's get our `./db-mongoose.js` file wrapped up. Open it and let's add:
```
const mongoose = require('mongoose');

const { DATABASE_URL } = require('./config');

function dbConnect(url = DATABASE_URL) {
    return mongoose.connect(url, { useNewUrlParser: true })
    .catch(err => {
        console.error('Mongoose failed to connect');
        console.error(err);
    });
}

function dbDisconnect() {
    return mongoose.disconnect();
}

function dbGet() {
    return mongoose;
}

module.exports = {
    dbConnect,
    dbDisconnect,
    dbGet
};
```

Here we're importing mongoose and our DATABASE_URL(we'll get to this in a moment!). We setup our dbConnect() function, which takes our Database_url, connect with mongoose.connect, and setup a catch incase of an error. Followed by a few more connection functions, and then export those functions!

All of the heavy lifting is now done! Just a few finishing touches and we'll be ready to unveil our Frankenstein Mongo-ster! *cackles maniacally* :v

So, let's setup our`./.gitignore` file. This file is open to modification, but for most apps, I use this template. Hopefully it will serve all your needs, aswell.
```
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Directory for instrumented libs generated by jscoverage/JSCover
lib-cov

# Coverage directory used by tools like istanbul
coverage

# nyc test coverage
.nyc_output

# Grunt intermediate storage (http://gruntjs.com/creating-plugins#storing-task-files)
.grunt

# Bower dependency directory (https://bower.io/)
bower_components

# node-waf configuration
.lock-wscript

# Compiled binary addons (https://nodejs.org/api/addons.html)
build/Release

# Dependency directories
node_modules/
jspm_packages/

# Typescript v1 declaration files
typings/

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env

.idea
```

Okay, last but certainly not least, we need to setup our `./.env` file. This will contain only 2 lines.
```
JWT_SECRET=whatever-you-want-your-secret-to-be
DATABASE_URL=mongodb://<dbuser>:<dbpassword>@<a-bunch-of-numbers>.mlab.com:<more-numbers>/programName
```

If you use mLab to host your free Mongodb, you'll be given a link when you create a database user through their GUI; it should be similar to what you see above. You'll need to add your username/password into it, but everything else should be unchanged.


That's it. After all of this, you should have a working API to register/create, login, and authenticate users for a MongoDB, Express, NodeJS application.
