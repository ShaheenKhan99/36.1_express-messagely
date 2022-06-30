const jwt = require("jsonwebtoken");
const Router = require("express").Router;
const router = new Router();

const User = require("../models/user");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");


/** POST /login - login: {username, password} => {token}
 *
 * Ensures that user's last-login is updated
 *
 **/
router.post("/login", async function (req, res, next) {
  try {
    let {username, password} = req.body;
    if (await User.authenticate(username, password)){
        let token = jwt.sign({username}, SECRET_KEY);
        User.updateLoginTimestamp(username);
      return res.json({token});
    } else {
      throw new ExpressError("Invalid username/password", 400);
    }
  }
  catch (err) {
    return next(err);
  }
});
  

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Updates their last-login
 */

router.post("/register", async function (req, res, next) {
  try {
    let {username} = await User.register(req.body);
    let token = jwt.sign({username}, SECRET_KEY);
    User.updateLoginTimestamp(username);
    return res.json({token});
  }
  catch (err) {
    if (err.code === "23505"){
      return next(new ExpressError("Username taken. Please pick another username, 400"));
    }
    return next(err);
  }
});


module.exports = router;