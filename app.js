require('dotenv').config(); 

const https = require('https');
const fs = require('fs');
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const xss = require('xss');
const session = require('express-session'); // Add session middleware
const flash = require('connect-flash');
const sendStatusUpdateEmail = require('./utils/mailer');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
// require('./passport-setup'); // Assuming this file mainly contains serialize/deserialize if used elsewhere
const port = 3000;
const saltRounds = 10;

const app = express();
app.use(flash());
app.use(express.static('public'));

// --- HTTPS Credentials ---
// Ensure these files exist or handle the error
let credentials = {};
try {
    const privateKey = fs.readFileSync('key.pem', 'utf8');
    const certificate = fs.readFileSync('cert.pem', 'utf8');
    credentials = { key: privateKey, cert: certificate };
} catch (err) {
    console.error("Error loading HTTPS key/cert files:", err.message);
    // Decide if you want to proceed without HTTPS or exit
    // process.exit(1);
}


// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
// IMPORTANT: Use a strong secret, ideally from environment variables
app.use(session({ secret: 'your_secret_key', resave: false, saveUninitialized: true })); // Session setup

// Initialize Passport *before* routes that use it
app.use(passport.initialize());
app.use(passport.session()); // Must be after express-session

// Flash message middleware (after session)
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error'); // Passport uses 'error' by default for flash
    res.locals.user = req.user || null; // Make user available to views if logged in
    next();
});


// Set EJS as the templating engine
app.set('view engine', 'ejs');

// MySQL Database Connection
// IMPORTANT: Use environment variables for credentials in production
// const db = mysql.createConnection({
//     host: '127.0.0.1',
//     user: 'root',
//     password: 'Devi@1708', // <-- SECURITY RISK: Hardcoded password
//     database: 'complaint_box'
// });

const db = mysql.createConnection({
    host: process.env.DB_HOST,         // Use env variable
    user: process.env.DB_USER,         // Use env variable
    password: process.env.DB_PASSWORD, // Use env variable
    database: process.env.DB_NAME      // Use env variable
});


db.connect((err) => {
    if (err) {
        console.error('FATAL ERROR: Cannot connect to MySQL:', err);
        process.exit(1); // Exit if DB connection fails
    }
    console.log('Connected to MySQL database');
});

// Use THIS LocalStrategy definition (includes logging from your original code)
passport.use(new LocalStrategy(
    (username, password, done) => {
        console.log(`Attempting login for username: ${username}`); // Log username attempt
        const query = 'SELECT * FROM admins WHERE username = ?';
        db.query(query, [username], (err, results) => {
            if (err) {
                console.error('Database error during login:', err); // Log DB errors
                return done(err);
            }
            if (results.length === 0) {
                console.log(`User not found: ${username}`); // Log user not found
                // Use the flash message key 'message' as configured in failureFlash options
                return done(null, false, { message: 'Incorrect username or password.' }); // Changed to generic message
            }

            const user = results[0];
            console.log(`User found: ${user.username}, comparing password...`); // Log user found

            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    console.error('Bcrypt comparison error:', err); // Log bcrypt errors
                    return done(err);
                }
                if (!isMatch) {
                    console.log(`Password mismatch for user: ${username}`); // Log password mismatch
                    return done(null, false, { message: 'Incorrect username or password.' }); // Changed to generic message
                }
                console.log(`Password match for user: ${username}. Login successful.`); // Log success
                return done(null, user);
            });
        });
    }
));


// Serialization/Deserialization (assuming these are correct for your 'admins' table)
passport.serializeUser((user, done) => {
    done(null, user.id); // Assuming 'id' is the primary key
});

passport.deserializeUser((id, done) => {
    const query = 'SELECT * FROM admins WHERE id = ?'; // Fetch necessary user data
    db.query(query, [id], (err, results) => {
        if (err) {
            return done(err, null);
        }
        // Important: handle case where user might have been deleted
        if (results.length === 0) {
            return done(null, false); // Indicate user not found
        }
        // Pass the user object (without sensitive data like password hash if possible)
        done(null, results[0]);
    });
});


// --- Routes ---

// GET login page
app.get('/login', (req, res) => {
    // Prevent logged-in users from seeing login page again
    if (req.isAuthenticated()) {
       return res.redirect('/login');
    }
    // Pass 'error' flash message (used by passport failureFlash)
    res.render('login', { error: req.flash('error') });
});

app.get('/adminlogin', (req, res) => {
    if (req.isAuthenticated()) {
       return res.redirect('/admin/pending');
    }
    // Pass 'error' flash message (used by passport failureFlash)
    res.render('dashboard', { error: req.flash('error') });
});



// POST login handler using Passport.js
app.post('/login', passport.authenticate('local', {
    successRedirect: '/admin/pending', // Redirect to pending complaints view
    failureRedirect: '/login',
    failureFlash: true // This uses the 'message' field from the strategy's done() callback
}));


// Logout route
app.get('/logout', (req, res, next) => { // Added next for error handling
    req.logout(err => {
        if (err) {
            console.error("Logout error:", err);
            req.flash('error_msg', 'Logout failed'); // Use consistent flash keys
            return next(err); // Propagate error
        }
        req.flash('success_msg', 'You have been logged out.'); // Use consistent flash keys
        res.redirect('/login');
    });
});

// Admin route to view PENDING complaints (Requires Login)
app.get('/admin/pending', (req, res) => {
    // **** FIX: Added Authentication Check ****
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Please log in to view this resource.');
        return res.redirect('/adminlogin');
    }
    const query = 'SELECT * FROM complaints WHERE status = "Pending" ORDER BY created_at DESC'; // Added ordering
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching pending complaints:', err);
            req.flash('error_msg', 'Error fetching complaints.'); // Use consistent flash keys
            // Render the page but show the error
             return res.render('admin', { complaints: [], error_msg: req.flash('error_msg') });
        }
        res.render('admin', { complaints: results }); // Pass results to admin.ejs
    });
});

app.get('/admin/resolved', (req, res) => {
    // **** FIX: Added Authentication Check ****
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Please log in to view this resource.');
        return res.redirect('/adminlogin');
    }
    const query = 'SELECT * FROM complaints WHERE status = "Resolved" ORDER BY created_at DESC'; // Added ordering
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching pending complaints:', err);
            req.flash('error_msg', 'Error fetching complaints.'); // Use consistent flash keys
            // Render the page but show the error
             return res.render('admin', { complaints: [], error_msg: req.flash('error_msg') });
        }
        res.render('admin', { complaints: results }); // Pass results to admin.ejs
    });
});

app.get('/admin/in-progress', (req, res) => {
    // **** FIX: Added Authentication Check ****
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Please log in to view this resource.');
        return res.redirect('/adminlogin');
    }
    const query = 'SELECT * FROM complaints WHERE status = "in-progress" ORDER BY created_at DESC'; // Added ordering
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching pending complaints:', err);
            req.flash('error_msg', 'Error fetching complaints.'); // Use consistent flash keys
            // Render the page but show the error
             return res.render('admin', { complaints: [], error_msg: req.flash('error_msg') });
        }
        res.render('admin', { complaints: results }); // Pass results to admin.ejs
    });
});

// Admin route to view PENDING complaints (Requires Login)
app.get('/admin', (req, res) => {
    // **** FIX: Added Authentication Check ****
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Please log in to view this resource.');
        return res.redirect('/adminlogin');
    }
    const query = 'SELECT * FROM complaints';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching pending complaints:', err);
            req.flash('error_msg', 'Error fetching complaints.'); // Use consistent flash keys
            // Render the page but show the error
             return res.render('admin', { complaints: [], error_msg: req.flash('error_msg') });
        }
        res.render('admin', { complaints: results }); // Pass results to admin.ejs
    });
});

// Delete complaint by ID (Admin action - Requires Login)
app.post('/delete-complaint/:id', (req, res) => {
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Please log in to perform this action.');
        return res.redirect('/adminlogin');
    }

    const complaintId = req.params.id;
    const query = 'DELETE FROM complaints WHERE id = ?';

    db.query(query, [complaintId], (err, result) => {
        if (err) {
            console.error('Error deleting complaint:', err);
            req.flash('error_msg', 'Error deleting complaint.');
            return res.redirect('/admin/pending');
        }

        req.flash('success_msg', 'Complaint deleted successfully.');
        res.redirect('/admin/pending');
    });
});


// Render the complaint submission form
app.get('/', (req, res) => {
    res.render('login');
});


// Handle complaint submission
app.post('/submit', (req, res) => {
    // Sanitize description where HTML/JS might be an issue if displayed raw
    const sanitizedInput = xss(req.body.description);
    // Note: Other fields (name, email, subject) might need sanitization or careful
    // handling (escaping) in EJS templates (<%- ... %>) if displayed.

    let { name, email, subject, description, password, anonymous } = req.body;

     // Basic Validation Example (can be expanded)
    if (!subject || !sanitizedInput || !password || (anonymous !== 'true' && (!name || !email))) {
        req.flash('error_msg', 'Please fill in all required fields.');
        return res.redirect('/');
    }

    if (anonymous === 'true') {
        name = 'Anonymous';
        email = 'Anonymous';
    }

    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            req.flash('error_msg', 'Error processing your request.'); // Use consistent flash key
            return res.redirect('/'); // Redirect back to form on error
        }

        // Insert data into the MySQL database, including initial status
        const query = 'INSERT INTO complaints (name, email, subject, password, description, status) VALUES (?, ?, ?, ?, ?, ?)';
        const initialStatus = 'Pending'; // Set initial status

        // Use the sanitized description here
        db.query(query, [name, email, subject, hashedPassword, sanitizedInput, initialStatus], (err, result) => {
            if (err) {
                console.error('Error inserting data into MySQL:', err);
                 req.flash('error_msg', 'Error saving complaint.'); // Use consistent flash key
                return res.redirect('/'); // Redirect back to form on error
            }

            const complaintId = result.insertId; // Get the inserted ID

            // Render the success page after successful submission
            res.render('success', { name: (name === 'Anonymous' ? 'User' : name), id: complaintId });
        });
    });
});
app.post('/admin/update-status/:id', async (req, res) => {
    const complaintId = req.params.id;
    const newStatus = req.body.status;

    try {
        const complaint = await Complaint.findById(complaintId);
        if (!complaint) {
            return res.status(404).send("Complaint not found");
        }

        complaint.status = newStatus;
        await complaint.save();

        // Send email to user
        sendStatusUpdateEmail(complaint.email, complaint._id, newStatus);

        res.redirect('/admin');
    } catch (error) {
        console.error('Status update error:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/update-status/:id', (req, res) => {
    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Authentication required.');
        return res.redirect('/login');
    }

    const complaintId = req.params.id;
    const newStatus = req.body.status;

    const allowedStatuses = ["pending", "in-progress", "resolved", "rejected"];
    if (!allowedStatuses.includes(newStatus)) {
        req.flash('error_msg', 'Invalid status provided.');
        return res.redirect('/admin/pending');
    }

    const updateStatusSql = 'UPDATE complaints SET status = ? WHERE id = ?';
    db.query(updateStatusSql, [newStatus, complaintId], (err, result) => {
        if (err) {
            console.error('Error updating complaint status:', err);
            req.flash('error_msg', 'Error updating status.');
            return res.redirect('/admin/pending');
        }

        if (result.affectedRows === 0) {
            req.flash('error_msg', `Complaint with ID ${complaintId} not found.`);
            return res.redirect('/admin/pending');
        }

        console.log(`Complaint ${complaintId} status updated to ${newStatus}`);
        req.flash('success_msg', `Complaint ${complaintId} status updated to ${newStatus}.`);

        const fetchComplaintSql = 'SELECT id, name, email FROM complaints WHERE id = ?';
        db.query(fetchComplaintSql, [complaintId], (fetchErr, complaintResult) => {
            if (fetchErr || complaintResult.length === 0) {
                console.error('Error fetching complaint for notification:', fetchErr);
                return res.redirect('/admin/pending');
            }

            const complaint = complaintResult[0];
            const email = complaint.email;

            if (email && email !== 'Anonymous') {
                const notificationMessage = `Your complaint (ID: ${complaintId}) status has been updated to: ${newStatus}`;
                const insertNotificationSql = 'INSERT INTO notifications (complaint_id, message, created_at) VALUES (?, ?, NOW())';

                db.query(insertNotificationSql, [complaintId, notificationMessage], (notifyErr, notificationResult) => {
                    if (notifyErr) {
                        console.error(`Error creating notification for complaint ${complaintId}:`, notifyErr.sqlMessage || notifyErr);
                    } else {
                        console.log(`Notification created for complaint ${complaintId}`);
                    }

                    // Send Email Notification
                    const emailMessage = `Hello ${complaint.name},\n\nYour complaint (ID: ${complaintId}) status has been updated to: ${newStatus}.\n\nRegards,\nComplaint Cell Team`;
                    sendStatusUpdateEmail(email, 'Complaint Status Update', emailMessage)
                        .then(() => {
                            console.log(`Email sent to ${email} for complaint ${complaintId}`);
                            return res.redirect('/admin/pending');
                        })
                        .catch((emailErr) => {
                            console.error(`Failed to send email for complaint ${complaintId}:`, emailErr);
                            return res.redirect('/admin/pending');
                        });
                });
            } else {
                console.log(`Complaint ${complaintId} is anonymous or missing email. No notification generated.`);
                return res.redirect('/admin/pending');
            }
        });
    });
});


// REMOVED: This route '/update-status' was incomplete and conflicted with '/update-status/:id'
// const { sendNotification } = require('./emailService'); // Was part of removed route
// app.post('/update-status', (req, res) => { ... });


// Route to render the track-status form
app.get('/track-status', (req, res) => {
    res.render('track-status');  // Renders the form to check complaint status
});

// Track complaint status result
app.get('/track-status-result', (req, res) => {
    const { complaintId, password } = req.query;

    if (!complaintId || !password) {
        return res.render('status-result', { complaint: null, error: 'Complaint ID and Password are required.' });
    }

    // Query to fetch complaint by ID including the password hash
    db.query('SELECT * FROM complaints WHERE id = ?', [complaintId], (err, result) => {
        if (err) {
            console.error('Error fetching complaint:', err);
            return res.status(500).render('status-result', { complaint: null, error: 'Error fetching complaint data.' });
        }

        if (result.length > 0) {
            const complaint = result[0];

            // Compare input password with stored hashed password
            bcrypt.compare(password, complaint.password, (compareErr, isMatch) => {
                if (compareErr) {
                    console.error('Error comparing password:', compareErr);
                    return res.status(500).render('status-result', { complaint: null, error: 'Error verifying password.' });
                }

                if (isMatch) {
                    // IMPORTANT: Do NOT send the password hash to the client/template
                    delete complaint.password;
                    // Render the status page with the complaint details
                    res.render('status-result', { complaint, error: null });
                } else {
                    // Password mismatch
                    res.render('status-result', { complaint: null, error: 'Incorrect password for this Complaint ID.' });
                }
            });
        } else {
            // Complaint ID not found
            res.render('status-result', { complaint: null, error: 'Complaint not found. Please check the ID.' });
        }
    });
});


// --- Server Start ---
// Use HTTPS server only if credentials were loaded successfully
if (credentials.key && credentials.cert) {
    const httpsServer = https.createServer(credentials, app);
    httpsServer.listen(port, () => {
        console.log(`HTTPS Server running securely on https://localhost:${port}/login`);
    });
} else {
    // Fallback to HTTP if HTTPS credentials are missing (useful for some dev setups)
    console.warn("WARNING: HTTPS credentials not found or loaded. Starting server using HTTP.");
    app.listen(port, () => {
        console.log(`HTTP Server running on http://localhost:${port}`);
    });
}