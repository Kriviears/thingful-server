'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');
const bcrypt = require('bcrypt');

const AuthService = {
  getUserWithUserName(db, user_name){
    return db('thingful_users')
      .where({ user_name })
      .first();
  },
  verifyJwt(token){
    return jwt.verify(token, config.JWT_SECRET, {
      algorithms: ['HS256']
    });
  },
  comparePasswords(password, hash){
    return bcrypt.compare(password, hash);
  },
  createJwt(subject, payload){
    return jwt.sign(payload, config.JWT_SECRET, {
      subject,
      algorithm: 'HS256'
    });
  }
};

module.exports = AuthService;