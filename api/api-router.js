const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("../api/api-model.js");
const restricted = require("./restricted-middleware.js");

router.post("/register", (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);
  //replace new user's password with hash instead of saving plain-text
  user.password = hash;

  db.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      console.log("/register error:", error);
      res.status(500).json(error);
    });
});

router.post("/login", (req, res) => {
  let { username, password } = req.body;

  db.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        // create token in this function
        const token = signToken(user);

        // sends user message and token
        res.status(200).json({
          token,
          message: `Welcome ${user.username}!`
        });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.get("/users", restricted, checkDept("admin"), (req, res) => {
  db.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// custom middlewares

// creates and assigns the token
function signToken(user) {
  const payload = {
    username: user.username,
    department: user.department
  };

  const secret = process.env.JWT_SECRET;

  const options = {
    expiresIn: "1h"
  };

  return jwt.sign(payload, secret, options); // notice the return
}

function checkDept(dept) {
  return function(req, res, next) {
    if (req.token && dept === req.token.department) {
      next();
    } else {
      res
        .status(403)
        .json({
          message: `You must be in ${dept} department to access this resource. You are in ${req.token.department}.`
        });
    }
  };
}

module.exports = router;
