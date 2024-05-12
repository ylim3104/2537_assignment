require("./utils.js");

const express = require("express");
const app = express();

const session = require("express-session");

require("dotenv").config();
const port = process.env.PORT || 2004;

const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const Joi = require("joi");
const expireTime = 60 * 60 * 1000; //expires in 1 hour
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("user");

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req,res,next) {
  if (isValidSession(req)) {
    next();
  }
  else {
    notifier.notify(restrict);
    res.redirect('/login');
    return;
  }
}

function isAdmin(req) {
  console.log(req.session.user_type);
  if (req.session.user_type == 'admin') {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", {error: "Not Authorized"});
    return;
  }
  else {
    next();
  }
}

const url = require("url");
const navLinks = [
  {name: "HOME", link: "/", svg: "#home"},
  {name: "SIGNUP", link: "/signup", svg: "#signup"},
  {name: "LOGIN", link: "/login", svg: "#login"},
  {name: "MEMBERS", link: "/members", svg: "#members"},
  {name: "ADMIN", link: "/admin", svg: "#admin"},
]

const notifier = require('node-notifier');
const restrict = {
  title: 'Your access is restricted',
  message: 'Log in to access the members only page',
  sound: 'true'
};

app.use("/", (req,res,next) => {
  app.locals.navLinks = navLinks;
  app.locals.currentURL = url.parse(req.url).pathname;
  next();
});

app.get("/", (req, res) => {
  var name = req.session.name;
  if (req.session.authenticated) {
    res.render("indexLogged", {name: name});
  } else {
    res.render("index");
  }
});

app.get("/signup", (req, res) => {
  if(!req.session.authenticated) {
    res.render("signup");
    return;
  }
  res.render("loggedin");
});

app.post("/signupSubmit", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().required();
  const nameValidation = schema.validate(name);
  const emailValidation = schema.validate(email);
  const passwordValidation = schema.validate(password);
  if (
    nameValidation.error != null ||
    emailValidation.error != null ||
    passwordValidation.error != null
  ) {
    res.render("signupSubmit", {nameValidation: nameValidation, emailValidation: emailValidation, passwordValidation: passwordValidation});
  } else {
    const result = await userCollection
      .find({ name: name })
      .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
      .toArray();
    console.log(result.length);
    console.log(result);
    if (result.length == 0) {
      var hashedPassword = await bcrypt.hash(password, saltRounds);
      await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: "user"
      });
      const newResult  = await userCollection
        .find({ name: name })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();
      console.log("Inserted user");
      req.session.authenticated = true;
      req.session.email = email;
      req.session.name = name;
      req.session.password = password;
      req.session.user_type = newResult[0].user_type;
      req.session.cookie.maxAge = expireTime;
      console.log(req.session.cookie.maxAge);
    } else {
      console.log("restore session");
      req.session.authenticated = true;
      req.session.email = email;
      req.session.name = name;
      req.session.password = password;
      req.session.user_type = result[0].user_type;
      req.session.cookie.maxAge = expireTime;
      console.log(req.session.cookie.maxAge);
    }
    res.redirect("/members");
    return;
  }
});

app.get("/login", (req, res) => {
    if (!req.session.authenticated) {
      res.render("login");
      return;
    }
    res.render("loggedin");
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;
  const schema = Joi.object({
    email: Joi.string().max(20).required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log("schema error" + JSON.stringify(validationResult));
    console.log(validationResult.error);
    res.redirect("/loginSubmit");
    return;
  }
  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/loginSubmit");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.email = email;
    req.session.password = password;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = result[0].expireTime;
    res.redirect("/members");
    return;
  } else {
    console.log("incorrect password");
    res.redirect("/loginSubmit");
    return;
  }
});

app.get("/loginSubmit", (req, res) => {
  res.render("loginSubmit");
});

app.get("/logout", (req, res) => {
  req.session.authenticated = false;
  res.redirect("/");
  return;
});

app.get("/signout", (req, res) => {
  req.session.authenticated = false;
  req.session.destroy();
  res.redirect("/");
  return;
});

app.get("/members", sessionValidation, async (req, res) => {
  var name = req.session.name;
  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();
  console.log(result);
  res.render("members", {name: name});
});

app.use(express.static(__dirname + "/public"));

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ name: 1, user_type: 1, _id: 1 })
    .toArray();
  let each = res.render("admin", { users: result });
  console.log(result);
});

app.get('/promote/:name', (req,res) => {
  const name = req.params.name;
  userCollection.updateOne(
    { name: name },
    { $set: { user_type: "admin" } }
  );
  console.log(`${name} is promoted to admin`);
  res.redirect("/admin");
  return;
});

app.get("/demote/:name", (req, res) => {
  const name = req.params.name;
  userCollection.updateOne({ name: name }, { $set: { user_type: "user" } });
  console.log(`${name} is demoted to user`);
  if(name == req.session.name) {
    req.session.user_type = "user";
  }
  res.redirect("/admin");
  return;
});

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
