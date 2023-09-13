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
const port = 3000

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
  response.render('login.ejs')
})

app.post('/login', (request, response) => {
  const { username, password } = request.body
  request.session.regenerate((error) => {
    if (error) console.log(error)
    if (username && password) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) console.log(error)
        if (results) {
          let databasePassword = results.password
          bcrypt.compare(password, databasePassword, (error, isMatch) => {
            if (isMatch) {
              if (error) console.log(error)
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
    if (error) console.log(error)
    if (username && password && confirmPassword) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) console.log(error)
        if (!results) {
          if (password == confirmPassword) {
            bcrypt.hash(password, 10, (error, hashedPassword) => {
              if (error) console.log(error)
              database.get(`INSERT INTO users (username, password ) VALUES (?, ?)`, [username, hashedPassword], (error) => {
                if (error) console.log(error)
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
    if (error) console.log(error)
    request.session.regenerate((error) => {
      if (error) console.log(error)
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
    if (error) console.log(error)
    if (results) {
      bcrypt.compare(currentPassword, results.password, (error, isMatch) => {
        if (error) console.log(error)
        if (isMatch && newPassword == confirmNewPassword) {
          bcrypt.hash(newPassword, 10, (error, hashedPassword) => {
            if (error) console.log(error)
            database.get('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (error, results) => {
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
  username = request.session.user
  database.get('DELETE FROM users WHERE username = ?', [username], (error, results) => {
    if (error) console.log(error)
    response.redirect('/logout')
  })
})

app.get('/oauth', (request, response) => {
  let redirectURL = request.query.redirectURL
  console.log(redirectURL)
  response.render('oauth.ejs', {
    redirectURL: redirectURL
  })
})

app.post('/oauth', (request, response) => {
  const {
    username,
    password,
    redirectURL
  } = request.body
  request.session.regenerate((error) => {
    if (error) console.log(error)
    if (username && password) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) console.log(error)
        if (results) {
          let databasePassword = results.password
          bcrypt.compare(password, databasePassword, (error, isMatch) => {
            if (isMatch) {
              if (error) console.log(error)
              request.session.user = username
              response.redirect(`${redirectURL}?username=${username}`)
            } else response.redirect(`/oauth?redirectURL=${redirectURL}`)
          })
        } else response.redirect(`/oauth?redirectURL=${redirectURL}`)
      })
    } else response.redirect(`/oauth?redirectURL=${redirectURL}`)
  })
})


app.listen(port, (err) => {
  if (err) {
    console.error(err)
  } else {
    console.log(`Running on port ${port}`)
  }
})