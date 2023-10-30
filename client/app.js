// Import Modules
const express = require('express')
const session = require('express-session')
const jwt = require('jsonwebtoken');


// Database Setup (not used here, however for independent projects using this API this would be useful for storing user data for that project)
// const sqlite3 = require('sqlite3').verbose()
// const database = new sqlite3.Database('./client/database.db', sqlite3.OPEN_READWRITE)


// Express Setup
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
/* Sets view engine to './client/views' for testing purposes. In independent projects this is not needed, but it is needed here due to both the client
  and server being stored in the same directory.*/
app.set('views', './client/views');
app.use(session({
  secret: 'D$jtDD_}g#T+vg^%}qpi~+2BCs=R!`}O',
  resave: false,
  saveUninitialized: false
}))

// Setup Constants

//Saves port of your choosing.
const port = 4000
/* Auth URL is wherever you'd like to redirect for verification/authentication. For example, when creating a plugin (which is most recommended for usage of this API),
   you'd want to set AUTH_URL to whatever your plugin is for in order for it to authenticate the user in both the plugin and server. */
const AUTH_URL = 'http://127.0.0.1:3000/oauth'
/* This is whatever your login page is set to, in this case, it is simply '/login'. */
const THIS_URL = 'http://127.0.0.1:4000/login'

// Functions

/* This authenticates the user and checks to see if the user is logged in. If so, it will continue the process like usual, if not, it will redirect you to the login
   page. */
function isAuthenticated(request, response, next) {
  if (request.session.user) next()
  else response.redirect('/login')
}


// Webpages

/* This is the homepage. It uses our function isAuthenticated to check for the user. When that succeeds, it tried to render your index/home page (depending on
   what you decide to name it) and carries over the 'request.session.user' data as the 'user' variable. Where this data comes from will be covered in '/login'. */
app.get('/', isAuthenticated, (request, response) => {
  try {
    response.render('index.ejs', { user: request.session.user })
  }
  catch (error) {
    response.send(error.message)
  }
})

/* This is what initially happens when you try to login. */
app.get('/login', (req, res) => {
  /* First, it checks if there is the query parameter of 'token'. This is used to check if there is a token present, which is carried over from the server side
   as said query parameter. */
  if (req.query.token) {
    console.log(req.query.token);
    /* If there is a token parameter present, then it decodes the token and stores it into a temporary variable. This is because, every time the user reconnects to the server,
    there will be a new token generated. */
    let tokenData = jwt.decode(req.query.token);
    /* It then saves the entirety of the token data into a cookie, with only the username data being stored in another. */
    req.session.token = tokenData;
    req.session.user = tokenData.username;
    /* From there, it redirects back to your homepage. */
    res.redirect('/');
    /* If there is not token, it redirects you to the server authentication page, with the query perameter of 'redirectURL' being given the THIS_URL variable,
    which should be your login page (or your page of choice).  */
  } else {
    res.redirect(AUTH_URL + `?redirectURL=${THIS_URL}`)
  };
})

// This logsout the user by overwriting the user cookie, which contains the username. It then saves the session and reloads it. It then redirects the user to the login page.
app.get('/logout', (request, response) => {
  request.session.user = null
  request.session.save((error) => {
    if (error) throw error
    response.redirect('/login')
  })
})

// This starts the client on whatever port you choose.
app.listen(port, (err) => {
  if (err) {
    console.error(err)
  } else {
    console.log(`Running on port ${port}`)
  }
})