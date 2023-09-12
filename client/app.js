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
const AUTH_PATH = 'http://127.0.0.1:3000/oauth'

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
  response.redirect(AUTH_PATH + `?redirectURL=${AUTH_PATH}`)
  // response.render('login.ejs')
})

app.post('/login', (request, response) => {
  const { username, password } = request.body
  request.session.regenerate((error) => {
    if (error) throw error
    if (username && password) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) throw error
        if (results) {
          let databasePassword = results.password
          bcrypt.compare(password, databasePassword, (error, isMatch) => {
            if (isMatch) {
              if (error) throw error
              request.session.user = username
              response.redirect('/')
            } else response.redirect('/login')
          })
        } else response.redirect('/login')
      })
    } else response.redirect('/login')
  })
})

app.get('/signup', (request, response) => {
  try {
    response.render('signup.ejs')
  }
  catch (error) {
    response.send(error.message)
  }
})

app.post('/signup', (request, response) => {
  const { username, password, confirmPassword } = request.body
  request.session.regenerate((error) => {
    if (error) throw error
    if (username && password && confirmPassword) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) throw error
        if (!results) {
          if (password == confirmPassword) {
            bcrypt.hash(password, 10, (error, hashedPassword) => {
              if (error) throw error
              database.get(`INSERT INTO users (username, password ) VALUES (?, ?)`, [username, hashedPassword], (error) => {
                if (error) throw error
                request.session.user = username
                response.redirect('/')
              })
            })
          } else response.redirect('/signup')
        } else response.redirect('/signup')
      })
    } else response.redirect('/signup')
  })
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

app.get('/changePassword', (request, response) => {
  try {
    response.render('changePassword.ejs')
  }
  catch (error) {
    response.send(error.message)
  }
})

app.post('/changePassword', (request, response) => {
  const { currentPassword, newPassword, confirmNewPassword } = request.body
  const username = request.session.user
  database.get(`SELECT password FROM users Where username = ?`, [username], (error, results) => {
    if (error) throw error
    if (results) {
      bcrypt.compare(currentPassword, results.password, (error, isMatch) => {
        if (error) throw error
        if (isMatch && newPassword == confirmNewPassword) {
          bcrypt.hash(newPassword, 10, (error, hashedPassword) => {
            if (error) throw error
            database.get('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (error, results) => {
              if (error) throw error
              response.redirect('/logout')
            })
          })
        } else response.redirect('/')
      })
    } else response.redirect('/')
  })
})


app.get('/deleteAccount', (request, response) => {
  username = request.session.user
  database.get('DELETE FROM users WHERE username = ?', [username], (error, results) => {
    if (error) throw error
    response.redirect('/logout')
  })
})


app.listen(port, (err) => {
  if (err) {
    console.error(err)
  } else {
    console.log(`Running on port ${port}`)
  }
})