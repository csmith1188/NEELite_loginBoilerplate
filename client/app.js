// Import Modules
const express = require('express')
const session = require('express-session')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const cookieParser = require("cookie-parser");
const jwt = require('jsonwebtoken');


// Database Setup
const database = new sqlite3.Database('./client/database.db', sqlite3.OPEN_READWRITE)


// Express Setup
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
app.set('views', './client/views');
app.use(session({
  secret: 'D$jtDD_}g#T+vg^%}qpi~+2BCs=R!`}O',
  resave: false,
  saveUninitialized: false
}))

// Setup Constants
const port = 4000
const AUTH_URL = 'http://127.0.0.1:3000/oauth'
const THIS_URL = 'http://127.0.0.1:4000/login'

// Functions
function isAuthenticated(request, response, next) {
  if (request.session.user) next()
  else response.redirect('/login')
}


// Webpages
app.get('/', isAuthenticated, (request, response) => {
  try {
    response.render('index.ejs', { user: request.session.user })
  }
  catch (error) {
    response.send(error.message)
  }
})

/*app.get('/login', (request, response) => {
  if (request.cookies.token) {
    response.redirect(AUTH_URL + `?redirectURL=${THIS_URL}&token=${request.cookies.token}`)
  }
  else if (request.session.user) {
    request.session.user = username
    request.session.save()
    response.redirect('/')
  } else response.redirect(AUTH_URL + `?redirectURL=${THIS_URL}`);
}) */

app.get('/login', (req, res) => {
  if (req.query.token) {
    console.log(req.query.token);
    let tokenData = jwt.decode(req.query.token);
    req.session.token = tokenData;
    req.session.user = tokenData.username;
    res.redirect('/');
  } else {
    res.redirect(AUTH_URL + `?redirectURL=${THIS_URL}`)
  };
})

app.get('/logout', (request, response) => {
  request.session.user = null
  request.session.save((error) => {
    if (error) throw error
    request.session.regenerate((error) => {
      if (error) throw error
      response.redirect('/login')
    })
  })
})

app.listen(port, (err) => {
  if (err) {
    console.error(err)
  } else {
    console.log(`Running on port ${port}`)
  }
})