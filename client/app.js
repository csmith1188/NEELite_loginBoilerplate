// Import Modules
const express = require('express')
const session = require('express-session')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')


// Database Setup
const database = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE)


// Express Setup
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
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

app.get('/login', (request, response) => {
  let username = request.query.username
  console.log(username)
  if (username) {
    request.session.user = username
    request.session.save()
    response.redirect('/')
  } else response.redirect(AUTH_URL + `?redirectURL=${THIS_URL}`)
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