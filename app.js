require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//passport-local is needed by the passportLocalMongoose, but we don't actually use it directly. 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate'); //has to be added as a plugin
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'This is our secret.',
    resave: false, // this option forces session to be saved back to your session store, even if it's not modified
    saveUninitialized: false //this option forces uninitialized, unmodified sessions to be saved anyway
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields:["password"]}); //will encrypt our entire database...
//it might be best to only encrypt a specific field

const User = new mongoose.model("user", userSchema);

passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets", //authorized redirect URI
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //because of google+ api.  
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_ID,
        clientSecret: process.env.FACEBOOK_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({
            facebookId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function (req, res) {
    res.render("home");
});

app.route("/auth/google")
    .get(passport.authenticate('google', {
        scope: ['profile']
    })); //this will be used for the popup

app.route("/auth/google/secrets") //callback after user completes popup
    .get(passport.authenticate("google", {
            failureRedirect: "/login"
        }),
        function (req, res) {
            // Successful authentication, redirect home.
            res.redirect("/secrets"); //will check if the user actually is authenticated
        });

app.route("/auth/facebook")
    .get(passport.authenticate('facebook')); //this will be used for the popup

app.route("/auth/facebook/secrets")
    .get(passport.authenticate("facebook", {
            failureRedirect: "/login"
        }),
        function (req, res) {
            // Successful authentication, redirect home.
            res.redirect('/secrets');
        });

app.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    .post(function (req, res) {
        const user = new User({
            user: req.body.username,
            password: req.body.password
        });
        req.login(user, function (err) {
            if (err) {
                console.log(err);
                res.redirect("/login");
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                }); // authenticates our user.
            }
        })
    });

app.route("/register")
    .get(function (req, res) {
        res.render("register");
    })
    .post(function (req, res) {
        //we'll use the passportLocalMongoose package to handle our interactions with mongoose
        User.register({
            username: req.body.username
        }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else { //no errors? then authenticate with passport. 
                passport.authenticate("local")(req, res, function () { //only triggered if authentication is successful and a cookie is saved
                    res.redirect("/secrets");
                })
            }
        });

    });

app.route("/secrets")
    .get(function (req, res) {
        User.find({"secret": {$exists: true}}, function(err, foundList){
            if(err){
                console.log(err);
            }else{
                res.render("secrets", {usersWithSecrets: foundList});
            }
        })
    });

app.route("/submit")
    .get(function (req, res) {
        if (req.isAuthenticated()) { //how to check if someone is authenticated.
            res.render("submit");
        } else {
            res.redirect("/login"); //not authenticated yet. 
        }
    })
    .post(function(req, res){
        const submittedSecret = req.body.secret;
        const userId = req.user.id;

        User.findById(req.user.id, function(err, result){
            if(err){
                console.log(err);
            }else{
                if(result){
                    result.secret = submittedSecret;
                    result.save(function(){
                        res.redirect("/secrets");
                    });
                }
            }
        })
    });

app.route("/logout")
    .get(function (req, res) {
        req.logout();
        res.redirect("/");
    });





app.listen(3000, function () {
    console.log("Connected to port 3000");
})