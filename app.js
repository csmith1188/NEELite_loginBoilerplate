// Import Modules
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();


// Database Setup
const database = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE);


// Express Setup
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(session({
  secret: 'AHDFOAHDFBIHBLFFOGUJBDYDHFOISADP',
  resave: false,
  saveUninitialized: false
}));


// Setup Variables
const port = 3000;
var data;


// Functions
function isAuthenticated (request, response, next) {
  if (request.session.user) {
    next();
  }
  else {
    response.redirect('/login');
  }
}


// Webpages
app.get('/', isAuthenticated, function(request, response) {
  try {
    response.render('index.ejs', {data: data, user:request.session.user});
  }
  catch(error) {
    response.send(error.message);
  }
})

app.get('/login', function(request, response) {
  try {
    response.render('login.ejs', {data: data});
  }
  catch(error) {
    response.send(error.message);
  }
})

app.post('/login', function(request, response) {
  const {username, password} = request.body;
  request.session.regenerate(function (error) {
  if (error) throw error;
  if (username && password) {
      database.get(`SELECT * FROM users Where username = ? AND password = ?`, [username, password], function(error, results) {
	      if (error) throw error;
	      if (results) {
          request.session.user = username;
          response.redirect('/');
	      }
      })
    } else response.redirect('/login');
  })
})

app.get('/signup', function(request, response) {
  try {
    response.render('signup.ejs', {data: data});
  }
  catch(error) {
    response.send(error.message);
  }
})

app.post('/signup', function(request, response) {
  const {username, password, confirmPassword} = request.body;
  request.session.regenerate(function (error) {
    if (error) throw error;
    if (username && password && confirmPassword) {
      database.get(`SELECT * FROM users Where username = ?`, [username], function(error, results) {
        if (error) throw error;
	      if (!results) {
          if (password == confirmPassword) {
            database.get('INSERT INTO users (username, password ) VALUES(?,?)', [username, password], function(error, results) {
	            if (error) throw error;
              request.session.user = username;
              response.redirect('/');
            })
          }
        }
      })
    } else response.redirect('/signup');
  })
})

app.get('/logout', function(request, response) {
  request.session.user = null;
  request.session.save(function (error) {
    if (error) throw error;
    request.session.regenerate(function (error) {
      if (error) next(error);
      response.redirect('/login');
    })
  })
})

app.get('/changePassword', function(request, response) {
  try {
    response.render('changePassword.ejs', {data: data});
  }
  catch(error) {
    response.send(error.message);
  }
})

app.post('/changePassword', function(request, response) {
  const {currentPassword, newPassword, confirmNewPassword} = request.body;
  const username = request.session.user;
  database.get('SELECT password FROM users Where username = ?', [username], function (error, results) {
    if (error) throw error;
    if (results.password) {
      if (results.password == currentPassword && newPassword == confirmNewPassword) {
        database.get('UPDATE users SET password = newPassword WHERE user = ?', [username], function (error, results) {
          response.redirect('/logout');
        })
      }
    } else response.redirect('/');
  })
})


app.listen(port, function(err) {
  if (err) {
    console.error(err);
  } else {
    console.log(`Running on port ${port}`);
  }
})
