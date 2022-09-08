// Import Modules
const fs = require("fs");
const express = require('express');
const session = require('express-session');


// Express Setup
const app = express();
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('view engine', 'ejs');
app.use(session({
  secret: 'AHDFOAHDFBIHBLFFOGUJBDYDHFOISADP',
  resave: false,
  saveUninitialized: false
}));


// Setup Variables
var data;


// Functions
function readData() {
  let rawData = fs.readFileSync('data.json');
  data = JSON.parse(rawData);
}

function writeData() {
  data = JSON.stringify(data);
  fs.writeFileSync('data.json', data);
}


function isAuthenticated (request, response, next) {
  if (request.session.user) {
    next()
  }
  else {
    response.redirect('/login')
  }
}


// Webpages
app.get('/', isAuthenticated, function(request, response) {
  try {
    response.render('index.ejs', {data: data})
  }
  catch(err) {
    response.send(err.message)
  }
})

app.get('/bootstrap', function(request, response) {
  try {
    response.sendFile(__dirname + '/node_modules/bootstrap/dist/css/bootstrap.min.css')
  }
  catch(err) {
    response.send(err.message)
  }
})

app.get('/login', function(request, response) {
  try {
    response.render('login.ejs', {data: data})
  }
  catch(err) {
    response.send(err.message)
  }
})

app.post('/login', function(request, response) {
  const {username, password} = request.body
  request.session.regenerate(function (err) {
    if (err) next(err)
    if (!username || !password) response.redirect('/login')
    else {
     if (data.accounts[username].password == password) {
       request.session.user = username;
       request.session.save(function (err) {
       if (err) return next(err);
          response.redirect('/');
        })
      } else response.redirect('/login');
    }
  })
});

app.get('/logout', function(request, response) {
  request.session.user = null;
  request.session.save(function (err) {
    if (err) next(err);
    request.session.regenerate(function (err) {
      if (err) next(err);
      response.redirect('/login')
    })
  })
});


readData();
app.listen(3000)
