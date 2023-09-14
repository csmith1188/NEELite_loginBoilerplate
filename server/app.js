// Import Modules
const express = require('express')
const session = require('express-session')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')

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
const port = 3000


// Functions
function isAuthenticated(request, response, next) {
  if (request.session.username) next()
  else response.redirect('/login')
}


// Webpages
app.get('/', isAuthenticated, (request, response) => {
  response.render('index.ejs', { user: request.session.username })
})

app.get('/login', (request, response) => {
  response.render('login.ejs')
})

app.post('/login', (request, response) => {
  const { username, password } = request.body

  if (username && password) {
    database.get(`SELECT * FROM users Where username = ?`, [username], (error, user) => {
      if (error) console.log(error)
      if (user) {
        let databasePassword = user.password
        bcrypt.compare(password, databasePassword, (error, isMatch) => {
          if (isMatch) {
            if (error) console.log(error)
            request.session.username = username
            response.redirect('/')
          } else response.redirect('/login')
        })
      } else response.redirect('/login')
    })
  } else response.redirect('/login')
})

app.get('/signup', (request, response) => {
  response.render('signup.ejs')
})

app.post('/signup', (request, response) => {
  const { username, password, confirmPassword } = request.body

  if (username && password && confirmPassword) {
    database.get(`SELECT * FROM users Where username = ?`, [username], (error, user) => {
      if (error) console.log(error)
      if (!user) {
        if (password == confirmPassword) {
          bcrypt.hash(password, 10, (error, hashedPassword) => {
            if (error) console.log(error)
            let secret = crypto.randomBytes(512)
            secret = secret.toString('hex')
            database.get(`INSERT INTO users (username, password, secret) VALUES (?, ?, ?)`, [username, hashedPassword, secret], (error) => {
              if (error) {
                console.log(error)
              }
              else {
                request.session.username = username
                response.redirect('/')
              }
            })
          })
        } else response.redirect('/signup')
      } else response.redirect('/signup')
    })
  } else response.redirect('/signup')
})

app.get('/logout', (request, response) => {
  request.session.username = null
  request.session.save((error) => {
    if (error) console.log(error)
    response.redirect('/login')
  })
})

app.get('/changePassword', (request, response) => {
  response.render('changePassword.ejs')
})

app.post('/changePassword', (request, response) => {
  const { currentPassword, newPassword, confirmNewPassword } = request.body
  const username = request.session.username
  database.get(`SELECT password FROM users Where username = ?`, [username], (error, user) => {
    if (error) console.log(error)
    if (user) {
      bcrypt.compare(currentPassword, user.password, (error, isMatch) => {
        if (error) console.log(error)
        if (isMatch && newPassword == confirmNewPassword) {
          bcrypt.hash(newPassword, 10, (error, hashedPassword) => {
            if (error) console.log(error)
            database.run('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (error) => {
              if (error) console.log(error)
              response.redirect('/logout')
            })
          })
        } else response.redirect('/')
      })
    } else response.redirect('/')
  })
})


app.get('/deleteAccount', (request, response) => {
  username = request.session.username
  database.run('DELETE FROM users WHERE username = ?', [username], (error) => {
    if (error) console.log(error)
    response.redirect('/logout')
  })
})

app.get('/oauth', (request, response) => {
  let { redirectURL, token } = request.query
  response.render('oauth.ejs', {
    redirectURL: redirectURL,
    token: token
  })
})

app.post('/oauth', (request, response) => {
  const {
    username,
    password,
    redirectURL,
    token
  } = request.body

  if (token) {
    console.log('is token')
    console.log(token)
    console.log(jwt.decode(token))
  }

  if (username && password) {
    database.get(`SELECT * FROM users Where username = ?`, [username], (error, user) => {
      if (error) console.log(error)
      if (user) {
        let databasePassword = user.password
        bcrypt.compare(password, databasePassword, (error, isMatch) => {
          if (isMatch) {
            if (error) console.log(error)
            request.session.username = username
            let token = jwt.sign({ username: username }, user.secret, {
              expiresIn: '5d'
            })
            response.redirect(`${redirectURL}?token=${token}`)
          } else response.redirect(`/oauth?redirectURL=${redirectURL}`)
        })
      } else response.redirect(`/oauth?redirectURL=${redirectURL}`)
    })
  } else response.redirect(`/oauth?redirectURL=${redirectURL}`)
})


app.listen(port, (err) => {
  if (err) {
    console.error(err)
  } else {
    console.log(`Running on port ${port}`)
  }
})