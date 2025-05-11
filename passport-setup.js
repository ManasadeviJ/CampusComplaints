const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mysql = require('mysql2');


// MySQL Database Connection
const db = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: 'Devi@1708',
    database: 'complaint_box'
});


// Define the local strategy for Passport.js
passport.use(new LocalStrategy(
  (username, password, done) => {
    const query = 'SELECT * FROM admin WHERE username = ?';
    db.query(query, [username], (err, results) => {
      if (err) return done(err);
      if (results.length === 0) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const admin = results[0];

      bcrypt.compare(password, admin.password, (err, isMatch) => {
        if (err) return done(err);
        if (isMatch) {
          return done(null, admin);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  }
));

// Serialize user for the session
passport.serializeUser((admin, done) => {
  done(null, admin.id);
});

// Deserialize user from the session
passport.deserializeUser((id, done) => {
  const query = 'SELECT * FROM admin WHERE id = ?';
  db.query(query, [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});
