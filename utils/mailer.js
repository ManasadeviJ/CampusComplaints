// // mailer.js
// const nodemailer = require('nodemailer');

// const transporter = nodemailer.createTransport({
//     service: 'Gmail',
//     auth: {
//         user: 'manasadevijpf@gmail.com',       // replace with your email
//         pass: 'boxbox'      // use an app password, not your real password
//     }
// });

// const sendStatusUpdateEmail = (to, complaintId, newStatus) => {
//     const mailOptions = {
//         from: 'manasadevijpf@gmail.com',
//         to,
//         subject: `Complaint #${complaintId} Status Updated`,
//         text: `Hello,\n\nThe status of your complaint (ID: ${complaintId}) has been updated to: ${newStatus}.\n\nThank you for your patience.\n\n- Complaint Management Team`
//     };

//     transporter.sendMail(mailOptions, (error, info) => {
//         if (error) {
//             console.error('Error sending mail:', error);
//         } else {
//             console.log('Email sent:', info.response);
//         }
//     });
// };

// module.exports = sendStatusUpdateEmail;

// ./utils/mailer.js
const nodemailer = require('nodemailer');

// --- No need to require('dotenv').config() here again ---
// It's already loaded by app.js

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER,         // Use env variable
        pass: process.env.EMAIL_APP_PASSWORD  // Use env variable
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Change the 'from' address to use the env variable if you defined EMAIL_FROM
// Otherwise, construct it or keep it as is.
async function sendStatusUpdateEmail(toEmail, subject, text) {
    console.log(`Attempting to send email via mailer.js to: ${toEmail} with subject: ${subject}`);

    const mailOptions = {
        // Example using EMAIL_USER if EMAIL_FROM is not set in .env
        from: `"Complaint Cell" <${process.env.EMAIL_USER}>`,
        // Or use EMAIL_FROM directly if set: from: process.env.EMAIL_FROM,
        to: toEmail,
        subject: subject,
        text: text,
    };

    try {
        let info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully via mailer.js: %s', info.messageId);
        // return info; // Optional
    } catch (error) {
        console.error('Error sending email via mailer.js:', error);
        throw error;
    }
}

module.exports = sendStatusUpdateEmail;