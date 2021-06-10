/////////////////////REQUIRED/////////////////////
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongooose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

/////////////////////PASSPORT SETUP/////////////////////
app.use(session({
  secret: "This is the super secret key",
  resave: false,
  saveUninitialized: false
}));

//use passport to manage user session
app.use(passport.initialize());
app.use(passport.session());

/////////////////////MONGOOSE & ENCRYPTION SETUP/////////////////////
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
//for DeprecationWarning: collection.ensureIndex is deprecated. Use createIndexes instead.
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  secret: String,
  googleId: String,
  facebookId: String,
});

//set up plugins with mongoose
userSchema.plugin(passportLocalMongooose);
userSchema.plugin(findOrCreate)

//setting up basic encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

//create local login strategy
passport.use(User.createStrategy());

//cookie session start & end for local login strategy using passport-local-mongoose
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//serialize and deserialize for any login strategy
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//create Google login strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    //findOrCreate not a function of passport, create function to check if user exists or install mongoose-findorcreate
    User.findOrCreate({ googleId: profile.id }, function (err, user){
      return cb(err, user);
    });
  }
));

//create Facebook login strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

/////////////////////HOME PAGE/////////////////////
app.get("/", function(req, res){
  res.render("home");
});

/////////////////////AUTHORIZATION VIA GOOGLE/////////////////////
// note no callback function
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

/////////////////////AUTHORIZATION VIA FACEBOOK /////////////////////
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

/////////////////////SECRETS PAGE/////////////////////
app.route("/secrets")

.get(function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers){
        res.render("secrets",
        {usersWithSecrets: foundUsers});
      }
    }
  });
});

/////////////////////SUBMIT PAGE/////////////////////
app.route("/submit")
.get(function(req, res){
  //checks if user is authenicated
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

.post(function(req, res){
  const submittedSecret = req.body.secret;

  //user information is stored in req by passport
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets")
        });
      }
    }
  });
});

/////////////////////LOGIN PAGE/////////////////////
app.route("/login")

.get(function(req, res){
  res.render("login");
})

.post(function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      //creates cookie in browser authenticating user until end of session
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

//authentication using bcrypt
// .post(function(req, res){
//   const username = req.body.username;
//   const password = req.body.password;
//
//   User.findOne({email: username}, function(err, foundUser){
//     if (err){
//       console.log(err);
//     } else {
//       if (foundUser){
//         bcrypt.compare(password, foundUser.password, function(err, result){
//           if (result === true) {
//             res.render("secrets");
//           }
//         });
//       }
//     }
//   })
// });

/////////////////////REGISTER PAGE/////////////////////
app.route("/register")

.get(function(req, res){
  res.render("register");
})

.post(function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    } else {
      //creates cookie in browser authenticating user until end of session
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

//authentication using bcrypt
// .post(function(req, res){
//
//   bcrypt.hash(req.body.password, saltRounds, function(err, hash){
//     const newUser = new User({
//       email: req.body.username,
//       password: hash
//     });
//
//     newUser.save(function(err){
//       if (err) {
//         console.log(err);
//       } else {
//         res.render("secrets");
//       }
//     })
//   });
// });

/////////////////////LOGOUT PAGE/////////////////////
app.route("/logout")

.get(function(req, res){
  req.logout();
  res.redirect("/");
});

/////////////////////START SERVER /////////////////////
app.listen(3000, function (){
  console.log("Server started on port 3000");
})
