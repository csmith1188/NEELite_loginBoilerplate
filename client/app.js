// Import Modules
const express = require('express')
const session = require('express-session')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')

// Express Setup
const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
app.use(session({
  secret: 'D$jtDD_}g#T+vg^%}qpi~+2BCs=R!`}O',
  resave: false,
  saveUninitialized: false
}))

// Setup Constants
const port = 4000
const AUTH_URL = 'http://localhost:3000/oauth'
const THIS_URL = 'http://localhost:4000/login'

// Functions
function isAuthenticated(request, response, next) {
  if (request.session.user) next()
  else response.redirect('/login')
}


// Webpages
app.get('/', isAuthenticated, (request, response) => {
  response.render('index.ejs', { user: request.session.user })
})

app.get('/login', (request, response) => {
  let queryToken = request.query.token
  let cookieToken = request.cookies.token // Change this line

  if (cookieToken) {
    response.redirect(`${AUTH_URL}?redirectURL=${THIS_URL}&token=${cookieToken}`)
  }

  if (queryToken) {
    let tokenData = jwt.decode(queryToken)
    request.session.user = tokenData.username
    request.session.save()
    response.cookie('token', queryToken, {
      httpOnly: true, // Add this line
      maxAge: tokenData.exp - Math.round(Date.now() / 1000),
    })
    response.redirect('/')
  }

  if (!cookieToken && !queryToken) {
    response.redirect(`${AUTH_URL}?redirectURL=${THIS_URL}`)
  }
})


app.get('/logout', (request, response) => {
  request.session.user = null
  request.session.save((error) => {
    if (error) throw error
    response.clearCookie('token')
    response.redirect('/login')
  })
})

app.listen(port, (err) => {
  if (err) {
    console.error(err)
  } else {
    console.log(`Running on port ${port}`)
  }
})