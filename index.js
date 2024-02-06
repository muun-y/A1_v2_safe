require("./utils");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const database = include("databaseConnection");
const db_utils = include("database/db_utils");
const db_users = include("database/users");
const success = db_utils.printMySQLVersion();

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.9fd4byt.mongodb.net/?retryWrites=true&w=majority`,
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
    cookie: {
      secure: false, // Set to true if using HTTPS
      maxAge: 3600000, // 1 hour in milliseconds
    },
    autoRemove: "interval",
    autoRemoveInterval: 60, // Sessions older than 1 hour will be removed every minute
    encrypt: true, // Enable encryption for session data (this is usually the default)
  })
);

app.get("/", (req, res) => {
  res.render("index");
});

//prevent HTML injection
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

const unescapeHtml = (safe) => {
  return safe
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'");
};

app.get("/createTables", async (req, res) => {
  const create_tables = include("database/create_tables");

  var success = create_tables.createTables();
  if (success) {
    res.render("successMessage", { message: "Created tables." });
  } else {
    res.render("errorMessage", { error: "Failed to create tables." });
  }
});

app.get("/login", (req, res) => {
  const errorMessage = req.query.errorMessage;
  res.render("login");
});

app.get("/signup", (req, res) => {
  // Check for the error query parameter
  const errorMessage = req.query.error;

  res.render("signup", { error: errorMessage });
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  var escapeUsername = escapeHtml(username);

  // Input validation
  if (!username || !password) {
    // If any of the fields are empty, redirect back to /signup with an error message
    const errorMessage = encodeURIComponent(
      "Please provide both username and password."
    );
    return res.redirect("/signup?error=" + errorMessage);
  }

  var hashedPassword = bcrypt.hashSync(password, saltRounds);

  var success = await db_users.createUser({
    user: escapeUsername,
    hashedPassword: hashedPassword,
  });

  if (success) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
  } else {
    // If user creation fails, redirect back to /signup with an appropriate error message
    const errorMessage = encodeURIComponent("Username already exists.");
    res.redirect("/signup?error=" + errorMessage);
  }
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  var errorMessage = "";

  var unescapeusername = unescapeHtml(username);

  var results = await db_users.getUser({
    user: unescapeusername,
    hashedPassword: password,
  });

  if (results) {
    if (results.length == 1) {
      // there should only be 1 user in the db that matches
      if (bcrypt.compareSync(password, results[0].password)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/loggedIn");
        return;
      } else {
        console.log("invalid password");
        errorMessage = "INVALID PASSWORD. Please try again.";
        return res.redirect("/login?errorMessage=" + errorMessage);
      }
    } else {
      console.log(
        "invalid number of users matched: " + results.length + " (expected 1)."
      );
      errorMessage = "User not found. Try again";
      return res.redirect("/login?errorMessage=" + errorMessage);
    }
  }
  res.render("login", { error: errorMessage || "" });
});

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (!isValidSession(req)) {
    req.session.destroy();
    res.redirect("/login");
    return;
  } else {
    next();
  }
}

app.use("/loggedin", sessionValidation);

app.get("/loggedin", (req, res) => {
  res.render("loggedin", {
    username: req.session.username,
  });
});

app.use(express.static("public"));
app.get("/members", (req, res) => {
  var isAuthenticated = req.session.authenticated;

  if (!isAuthenticated) {
    return res.redirect("/");
  } else {
    var username = req.session.username;
    const getRandomImage = () => {
      const images = ["fluffy.gif", "cat3.gif", "Cute.gif"];
      const randomIndex = Math.floor(Math.random() * images.length);
      return images[randomIndex];
    };

    res.render("members", {
      authenticated: isAuthenticated,
      username: username,
      randomImage: getRandomImage(),
    });
  }
});

app.get("/signout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/api", (req, res) => {
  var user = req.session.user;
  var user_type = req.session.user_type;
  console.log("api hit ");

  var jsonResponse = {
    success: false,
    data: null,
    date: new Date(),
  };

  if (!isValidSession(req)) {
    jsonResponse.success = false;
    res.status(401); //401 == bad user
    res.json(jsonResponse);
    return;
  }

  if (typeof id === "undefined") {
    jsonResponse.success = true;
    if (user_type === "admin") {
      jsonResponse.data = ["A", "B", "C", "D"];
    } else {
      jsonResponse.data = ["A", "B"];
    }
  } else {
    if (!isAdmin(req)) {
      jsonResponse.success = false;
      res.status(403); //403 == good user, but, user should not have access
      res.json(jsonResponse);
      return;
    }
    jsonResponse.success = true;
    jsonResponse.data = [id + " - details"];
  }

  res.json(jsonResponse);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
