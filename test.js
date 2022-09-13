const bcrypt = require('bcrypt');

const password = 'pass123'
var hashedPassword;

bcrypt.hash(password, 10, (error, hash) => {
  if (error) return console.log('Cannot encrypt');
  hashedPassword = hash;
  console.log('hashedPassword1 = ', hashedPassword);
  console.log(hash);
})

console.log('hashedPassword2 = ', hashedPassword);
bcrypt.compare(password, hashedPassword, async (error, isMatch) => {
  if (isMatch) {
  } else
})