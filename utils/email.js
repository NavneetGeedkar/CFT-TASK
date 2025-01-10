const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

exports.sendResetEmail = (to, token) => {
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;
    const mailOptions = {
        from: process.env.SMTP_USER,
        to,
        subject: 'Password Reset',
        text: `Click this link to reset your password: ${resetLink}`,
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) console.error(err);
    });
};
