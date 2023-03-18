// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express');
const bcrypt = require('bcryptjs');

const User = require('../users/users-model');
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware');

const router = express.Router();

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register',checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const newUser = { username, password: hash };

    const result = await User.add(newUser);
    res.status(200).json({ 'user_id': result.user_id, 'username': result.username })
  } catch (err) {
    next(err);
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [user] = await User.findBy({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      res.json({ message: `Welcome ${user.username}!` });
    } else {
      next({ status: 401, message: 'Invalid credentials' });
    }
  } catch (err) {
    next(err);
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', async (req, res) => {
  if (req.session.user) {
    const { uername } = req.session.user;
    req.session.destroy(err => {
      if (err) {
        res.json({ message: 'problem logging out' });
      } else {
        res.json({ message: 'logged out' });
      }
    })
  } else {
    res.json({ message: 'no session' });
  }
})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;