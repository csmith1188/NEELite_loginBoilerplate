// Import Modules
const express = require('express')
const session = require('express-session')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken");
const crypto = require("crypto");


// Database Setup
const database = new sqlite3.Database('./server/database.db', sqlite3.OPEN_READWRITE)


// Express Setup
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs')
/* Sets view engine to './server/views' for testing purposes. This will not be present normally, as the client typically connects to a server not present
in the same file directory. For example, the client, 172.168.7.5:3000, would connect to the server, 172.168.9.6:3000.*/
app.set('views', './server/views');
app.use(session({
  secret: 'D$jtDD_}g#T+vg^%}qpi~+2BCs=R!`}O',
  resave: false,
  saveUninitialized: false
}))

// Setup Constants
const port = 3000

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

// This is the login page, which renders your login page.
app.get('/login', (request, response) => {
  response.render('login.ejs')
})

/* This is what happens after login data is submitted.*/
app.post('/login', (request, response) => {
  // It saves the username and password collected from the data submitted.
  const { username, password } = request.body
  // If both a username and password are saved, then it will grab data from the database where the username matches.
    if (username && password) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) console.log(error)
        if (results) {
          // Using these results, it will save the password present in the database to a variable.
          let databasePassword = results.password
          // It then compares the password submitted and the database password to see if they match.
          bcrypt.compare(password, databasePassword, (error, isMatch) => {
            if (isMatch) {
              if (error) console.log(error)
              // If they do, save the username to the user cookie and redirect to the home page.
              request.session.user = username
              response.redirect('/')
            // If the passwords do not match, redirect to the '/login' page again to resubmit data.
            } else response.redirect('/login')
          })
        // If there are no results in the database, redirect to the '/login' page again to resubmit data.
        } else response.redirect('/login')
      })
    // If there is no username, no password, or neither present in the submitted data, then redirect to the '/login' page again to resubmit data.
    } else response.redirect('/login')
})

// This is what happens when the user tries to sign up. It simply renders the 'signup.ejs' page.
app.get('/signup', (request, response) => {
  try {
    response.render('signup.ejs')
  }
  catch (error) {
    response.send(error.message)
  }
})

/* This is what happens after the user submits signup data.*/
app.post('/signup', (request, response) => {
  // It saves the data, including the confirmed password.
  const { username, password, confirmPassword } = request.body
  // If all of the data is collected, it tries to get data from the database based on the username.
    if (username && password && confirmPassword) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) console.log(error)
        //If there are no results returned, meaning the username doesn't exist, and if the password and the confirmed password match, then it encrypts the password.
        if (!results) {
          if (password == confirmPassword) {
            bcrypt.hash(password, 10, (error, hashedPassword) => {
              if (error) console.log(error);
              // Then it creates a secret based on 512 random bytes collected and saves it after converting it to a hex string.
              let secret = crypto.randomBytes(512);
              secret = secret.toString('hex');
              // Afterwards, it inserts the data into the database, creating a new user.
              database.get(`INSERT INTO users (username, password, secret ) VALUES (?, ?, ?)`, [username, hashedPassword, secret], (error) => {
                if (error) console.log(error)
                // It also creates a user cookie which the username is stored into, and then it redirects to the homepage.
                request.session.user = username
                response.redirect('/')
              })
            })
          // If the passwords don't match, redirect to the sign up page to re-enter data.
          } else response.redirect('/signup')
        // If there are results in the database, then redirect to the sign up page to re-enter results.
        } else response.redirect('/signup')
      })
    // If there is no username, password, and/or confirmed password, then redirect to the sign up page to re-enter data.
    } else response.redirect('/signup')
})

// This is what happens when the user tries to log out.  
app.get('/logout', (request, response) => {
  // It resets the session.user (or the user "cookie", as referred to earlier), and then it saves it.
  request.session.user = null
  request.session.save((error) => {
    if (error) console.log(error)
    // After the new user cookie is saved, it redirects to the login page.
      response.redirect('/login')
  })
})

//This is what happens when the user tries to change their password. It simply renders the changePassword page.
app.get('/changePassword', (request, response) => {
  try {
    response.render('changePassword.ejs')
  }
  catch (error) {
    response.send(error.message)
  }
})

/* This is what happens when the user submits the changed password data.*/
app.post('/changePassword', (request, response) => {
  // It saves the current password, the new password, and the confirmed new password based on the submitted data.
  const { currentPassword, newPassword, confirmNewPassword } = request.body
  // It saves the user cookie data to a username variable.
  const username = request.session.user
  // It then get data from the database based on that username.
  database.get(`SELECT password FROM users Where username = ?`, [username], (error, results) => {
    if (error) console.log(error)
    // If there are results, then it compares the current password that was submitted to the password present in the database.
    if (results) {
      bcrypt.compare(currentPassword, results.password, (error, isMatch) => {
        if (error) console.log(error)
        // If it matches and the new password is the same as the confirmed new password, then it encrypts the new password and saves it to the database.
        if (isMatch && newPassword == confirmNewPassword) {
          bcrypt.hash(newPassword, 10, (error, hashedPassword) => {
            if (error) console.log(error)
            database.get('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (error, results) => {
              if (error) console.log(error)
              // Then it redirects the user to the logout page.
              response.redirect('/logout')
            })
          })
        // If the passwords don't match in either way, then it redirects the user to the home screen.
        } else response.redirect('/')
      })
    // If there are no results given from the database, then it redirects the user to the home screen.
    } else response.redirect('/')
  })
})

/* This is what happens when the user tries to delete their account.*/
app.get('/deleteAccount', (request, response) => {
  // It saves the user cookie to the username variable, then deletes the user in the database where the username matches.
  username = request.session.user
  database.get('DELETE FROM users WHERE username = ?', [username], (error, results) => {
    if (error) console.log(error)
    // Then it redirects the user to the logout page.
    response.redirect('/logout')
  })
})

/* This is what happens when the server tries to authenticate the user. It saves the redirectURL query parameter to a variable, andsends the redirectURL to the oauth page as
a variable. */
app.get('/oauth', (request, response) => {
  let redirectURL = request.query.redirectURL
  response.render('oauth.ejs', {
    redirectURL: redirectURL
  });
})

/* This is what happens after the user submits their authentication data. It saves the username, password, and the redirectURL that is submitted. If there is a username and
password submitted, then it gets results from the database that match the username. If there are results returned, it saves the database password to a variable. It then compares
the submitted password to the database password. */
app.post('/oauth', (request, response) => {
  const {
    username,
    password,
    redirectURL
  } = request.body
    if (username && password) {
      database.get(`SELECT * FROM users WHERE username = ?`, [username], (error, results) => {
        if (error) console.log(error)
        if (results) {
          let databasePassword = results.password
          console.log(results.password)
          bcrypt.compare(password, databasePassword, (error, isMatch) => {
            if (isMatch) {
              if (error) console.log(error)
              console.log(password)
              var uniToken = jwt.sign({ username: username }, results.secret, {expiresIn: '5d'});
              console.log(uniToken);
              response.redirect(`${redirectURL}?token=${uniToken}`);
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