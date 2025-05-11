const nodemailer = require('nodemailer');

// Configure the transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // or another email service
    auth: {
        user: 'your-email@gmail.com',
        pass: 'your-email-password' // Use environment variables for security
    }
});

const sendNotification = (to, subject, text) => {
    const mailOptions = {
        from: 'your-email@gmail.com',
        to,
        subject,
        text
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.log('Error sending email:', error);
        }
        console.log('Email sent:', info.response);
    });
};

module.exports = { sendNotification };
