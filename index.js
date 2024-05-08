require("./utils.js");

const express = require("express");
const app = express();

const session = require("express-session");

require("dotenv").config();
const port = process.env.PORT || 3000;

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

app.use(express.urlencoded({ extended: false }));

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

app.get("/", (req, res) => {
  var name = req.session.name;
  if (req.session.authenticated) {
    res.send(`
                Hello ${name}!
                <br>
                <button onClick="location.href='/members'">Go to Members Area</button>
                <br>
                <button onClick="location.href='/logout'">Log out</button>
                <button onClick="location.href='/signout'">Sign out</button>
        `);
  } else {
    res.send(`<button onClick="location.href='/signup'">Sign up</button>
                <br>
                <button onClick="location.href='/login'">Log in</button>
                `);
  }
});

app.get("/signup", (req, res) => {
  var html = `
    create user
    <form action='/signupSubmit' method='post'>
        <input name='name' type='text' placeholder='name'>
        <br>
        <input name='email' type='email' placeholder='email'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>Submit</button>
    </form>
    <button onClick="location.href='/'">Back</button>
    `;
  res.send(html);
});

app.post("/signupSubmit", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().required();
  const nameValidation = schema.validate(name);
  const emailValidation = schema.validate(email);
  const passwordValidation = schema.validate(password);
  var html = ``;
  if (nameValidation.error != null) {
    console.log(nameValidation.error);
    html += `
            Name is required.
            <br>
        `;
  }
  if (emailValidation.error != null) {
    console.log(emailValidation.error);
    html += `
            Email is required.
            <br>
        `;
  }
  if (passwordValidation.error != null) {
    console.log(passwordValidation.error);
    html += `
            Password is required.
            <br>
        `;
  }
  if (
    nameValidation.error != null ||
    emailValidation.error != null ||
    passwordValidation.error != null
  ) {
    html += `<a href="/signup">Try again</a>`;
    res.send(html);
  } else {
    const result = await userCollection
      .find({ email: email })
      .project({ name: 1, email: 1, password: 1, _id: 1 })
      .toArray();
    console.log(result.length);
    if (result.length == 0) {
      var hashedPassword = await bcrypt.hash(password, saltRounds);
      await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
      });
      console.log("Inserted user");
      req.session.authenticated = true;
      req.session.email = email;
      req.session.name = name;
      req.session.password = password;
      req.session.cookie.maxAge = expireTime;
      console.log(req.session.cookie.maxAge);
    } else {
      console.log("restore session");
      req.session.authenticated = true;
      req.session.email = email;
      req.session.name = name;
      req.session.password = password;
      req.session.cookie.maxAge = expireTime;
      console.log(req.session.cookie.maxAge);
    }
    res.redirect("/members");
    return;
  }
});

app.get("/login", (req, res) => {
  var html = `
    <form action='/loggingin' method='post'>
        log in
        <br>
        <input name='email' tupe='email' placeholder='email'>
        <br>
        <input name='password' type='password' placeholder='password'>
        <br>
        <button>Submit</button>
    </form>
    <button onClick="location.href='/'">Back</button>

    `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var name = req.session.name;
  var email = req.body.email;
  var password = req.body.password;
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().max(20).required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log("schema error" + JSON.stringify(validationResult));
    console.log(validationResult.error);
    res.redirect("/loginSubmit");
    return;
  }
  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();
  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/loginSubmit");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    res.redirect("/members");
    return;
  } else {
    console.log("incorrect password");
    res.redirect("/loginSubmit");
    return;
  }
});

app.get("/loginSubmit", (req, res) => {
  var html = `
            Invalid combination of email/password
            <br>
            <a href="/login">Try again</a>
        `;
  res.send(html);
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

app.get("/members", async (req, res) => {
  var name = req.session.name;
  if (req.session.authenticated) {
    console.log("user signed in");
  } else {
    console.log("no user");
  }
  var html = `
    <h1>Hello, ${name}.</h1>
    <br>
    `;
  var cat = Math.floor(Math.random() * 2) + 1;
  if (cat == 1) {
    html += `<img src='/babyCat.gif' style='width:300px;'>`;
  } else if (cat == 2) {
    html += `<img src='/computerCat.gif' style='width:300px;'>`;
  } else {
    html += `<img src='/surprisedCat.gif' style='width:300px;'>`;
  }
  html += `
    <br>
    <button onClick="location.href='/'">Main page</button>
    <button onClick="location.href='/logout'">Log out</button>
    <button onClick="location.href='/signout'">Sign out</button>
    `;

  const schema = Joi.required();
  const validationResult = schema.validate(name);
  if (validationResult.error != null) {
    if (!req.session.authenticated) {
      console.log(validationResult.error);
      res.redirect("/");
      return;
    } else {
      req.session.restore;
      console.log(req.session);
    }
  }
  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();
  console.log(result);
  res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.send("Page not found 404!!");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
