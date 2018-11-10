const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');

const { TEST_MONGODB_URI } = require('../config');

const User = require('../users/models/user');

const expect = chai.expect;

chai.use(chaiHttp);

describe('API - Users', function () {
  const username = 'exampleUser';
  const email = 'example@user.com';
  const password = 'examplePass';

  before(function () {
    return mongoose.connect(TEST_MONGODB_URI, { useNewUrlParser: true })
      .then(() => mongoose.connection.db.dropDatabase());
  });

  beforeEach(function () {
    return User.createIndexes();
  });

  afterEach(function () {
    return mongoose.connection.db.dropDatabase();
  });

  after(function () {
    return mongoose.disconnect();
  });

  describe('/api/users', function () {
    describe('POST', function () {
      it('Should create a new user', function () {
        let res;
        return chai
          .request(app)
          .post('/api/user')
          .send({ username, password, email })
          .then(_res => {
            res = _res;
            expect(res).to.have.status(201);
            expect(res.body).to.be.an('object');
            expect(res.body).to.have.keys('id', 'username', 'email');
            expect(res.body.id).to.exist;
            expect(res.body.username).to.equal(username);
            expect(res.body.email).to.equal(email);
            return User.findOne({ username });
          })
          .then(user => {
            expect(user).to.exist;
            expect(user.id).to.equal(res.body.id);
            expect(user.email).to.equal(email);
            return user.validatePassword(password);
          })
          .then(isValid => {
            expect(isValid).to.be.true;
          });
      });

      it('Should reject users with missing username', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ password, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Missing username in request body');
          });
      });

      it('Should reject users with missing password', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Missing password in request body');
          });

      });

      it('Should reject users with non-string username', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username: 1234, password, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'username\' must be type String');
          });
      });

      it('Should reject users with non-string password', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username, password: 1234, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'password\' must be type String');
          });
      });

      it('Should reject users with non-trimmed username', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username: ` ${username} `, password, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'username\' cannot start or end with a whitespace!');
          });
      });

      it('Should reject users with non-trimmed password', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username, password: ` ${password}`, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'password\' cannot start or end with a whitespace!');
          });
      });

      it('Should reject users with empty username', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username: '', password, email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'username\' must be at least 1 characters long');
          });
      });

      it('Should reject users with password less than 8 characters', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username, password: 'asdfghj', email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'password\' must be at least 8 characters long');
          });
      });

      it('Should reject users with password greater than 72 characters', function () {
        return chai
          .request(app)
          .post('/api/user')
          .send({ username, password: new Array(73).fill('a').join(''), email })

          .then(res => {
            expect(res).to.have.status(422);
            expect(res.body.message).to.equal('Field: \'password\' must be at most 72 characters long');
          });
      });

      it('Should reject users with duplicate username', function () {
        return User
          .create({
            username,
            password,
            email
          })
          .then(() => {
            return chai
              .request(app)
              .post('/api/user')
              .send({ username, password, email });
          })
          .then(res => {
            expect(res).to.have.status(400);
            expect(res.body.message).to.equal('The username already exists');
          });
      });
    });
  });
});