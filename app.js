// Import Modules
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');


// Database Setup
const database = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE);


// Express Setup
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'D$jtDD_}g#T+vg^%}qpi~+2BCs=R!`}O',
  resave: false,
  saveUninitialized: false
}));


// Setup Variables
const port = 3000;


// Functions
function isAuthenticated(request, response, next) {
  if (request.session.user) {
    next();
  }
  else {
    response.redirect('/login');
  }
}


// Webpages
app.get('/', isAuthenticated, function (request, response) {
  try {
    response.render('index.ejs', { user: request.session.user });
  }
  catch (error) {
    response.send(error.message);
  }
})

app.get('/login', function (request, response) {
  try {
    response.render('login.ejs');
  }
  catch (error) {
    response.send(error.message);
  }
})

app.post('/login', function (request, response) {
  const { username, password } = request.body;
  request.session.regenerate(function (error) {
    if (error) throw error;
    if (username && password) {
      database.get(`SELECT * FROM users Where username = ?`, [username], function (error, results) {
        if (error) throw error;
        if (results) {
          let databasePassword = results.password
          bcrypt.compare(password, databasePassword, (error, isMatch) => {
            if (isMatch) {
              if (error) throw error;
              request.session.user = username;
              response.redirect('/');
            } else response.redirect('/login');
          })
        } else response.redirect('/login')
      })
    } else response.redirect('/login')
  })
})

app.get('/signup', function (request, response) {
  try {
    response.render('signup.ejs');
  }
  catch (error) {
    response.send(error.message);
  }
})

app.post('/signup', function (request, response) {
  const { username, password, confirmPassword } = request.body;
  request.session.regenerate(function (error) {
    if (error) throw error;
    if (username && password && confirmPassword) {
      database.get(`SELECT * FROM users Where username = ?`, [username], (error, results) => {
        if (error) throw error;
        if (!results) {
          if (password == confirmPassword) {
            bcrypt.hash(password, 10, function (error, hashedPassword) {
              if (error) throw error;
              database.get(`INSERT INTO users (username, password ) VALUES (?, ?)`, [username, hashedPassword], (error) => {
                if (error) throw error;
                request.session.user = username;
                response.redirect('/');
              })
            })
          }
        }
      })
    } else response.redirect('/signup');
  })
})

app.get('/logout', function (request, response) {
  request.session.user = null;
  request.session.save(function (error) {
    if (error) throw error;
    request.session.regenerate(function (error) {
      if (error) next(error);
      response.redirect('/login');
    })
  })
})

app.get('/changePassword', function (request, response) {
  try {
    response.render('changePassword.ejs');
  }
  catch (error) {
    response.send(error.message);
  }
})

app.post('/changePassword', function (request, response) {
  const { currentPassword, newPassword, confirmNewPassword } = request.body;
  const username = request.session.user;
  database.get(`SELECT password FROM users Where username = ?`, [username], function (error, results) {
    if (error) throw error;
    if (results) {
      bcrypt.compare(currentPassword, results.password, (error, isMatch) => {
        if (error) throw error;
        if (isMatch && newPassword == confirmNewPassword) {
          bcrypt.hash(newPassword, 10, (error, hashedPassword) => {
            if (error) throw error;
            database.get('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username], (error, results) => {
              if (error) throw error;
              response.redirect('/logout')
            })
          })
        } else response.redirect('/')
      })
    } else response.redirect('/');
  })
})


app.get('/deleteAccount', function (request, response) {
  username = request.session.user
  database.get('DELETE FROM users WHERE username = ?', [username], (error, results) => {
    if (error) throw error;
    response.redirect('/logout')
  })
})


app.listen(port, function (err) {
  if (err) {
    console.error(err);
  } else {
    console.log(`Running on port ${port}`);
  }
})