const express = require('express');
const router = express.Router();
const User = require('../models/User.model');
const bcrypt = require('bcrypt');
const bcryptSalt = 10;
const passport = require('passport');
const ensureLogin = require('connect-ensure-login');

router.get("/login", (req, res, next) => {
  res.render("auth/login", { "message": req.flash("error") });
});

router.get('/signup', (req, res, next) => {
  res.render('auth/signup')
});

router.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("auth/private", { user: req.user });
});

router.get('/logout', (req, res, next) => {
  req.logout();
  res.redirect('/login');
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true,
  passReqToCallback: true
}));

router.post('/signup', (req, res, next) => {
  const {username, password} = req.body;

  if(username == "" | password == "") {
    res.render('auth/signup', {message: "Please enter a username & password"});
    return;
  }

  User.findOne({username})
    .then(user => {
      if(user !== null) {
        res.render('auth/signup', {message: "Username already exists!"});
        return;
      } 
      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);
      const newUser = new User({username, password: hashPass});

      newUser.save()
        .then(user => {
          res.redirect('/');
        })
        .catch(e => res.render('auth/signup', {message: "Error creating user!"}))
      
    })
    .catch(e => next(e))

});

router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('passport/private', { user: req.user });
});

module.exports = router;
