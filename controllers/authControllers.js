const db = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET ="navneetg"
const { sendResetEmail } = require('../utils/email');

// Signup
exports.signup = async (req, res) => {
    try {
        const { first_name, last_name, email, password } = req.body;
        const user = await db.query('SELECT * FROM users WHERE email=?', [email])
        if (user.rows.length>0){
            return res.status(401).json({
                success : false,
                msg: "User already exits",
            })
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await db.query('INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)',[
            first_name,
            last_name,
            email,
            hashedPassword,
        ])
        res.status(201).json({ message: 'User registered successfully',
            success : true,

            newUser:{
                id:newUser.insertId,
                first_name: first_name,
                last_name: last_name,
                email:email,
                password: hashedPassword,
            }
         });
}    
     catch(error){
return res.status(501).json({
    success: false,
    msg: "User Not Registered!"
})
}


// Login
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.rows.length === 0) 
            return res.status(401).json({ 
        success: false,
        message: 'User Not Found' 
    });

        const user= users.rows[0];
        const isPasswordValid = await bcrypt.compare(password, users.password);
        if (!isPasswordValid) 
            return res.status(401).json({ 
        success: false,
        message: 'Password Not Matched' });

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};



// Forgot Password
const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });

        const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '5m' });
        const resetTokenExpiry = new Date(Date.now() + 5 * 60000);
        await db.execute('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?', [
            resetToken,
            resetTokenExpiry,
            email,
        ]);

        sendResetEmail(email, resetToken);
        res.json({ message: 'Password reset link sent' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};



// Reset Password
const resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const [users] = await db.execute('SELECT * FROM users WHERE email = ? AND reset_token = ?', [
            decoded.email,
            token,
        ]);
        if (users.length === 0) return res.status(400).json({ message: 'Invalid or expired token' });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?', [
            hashedPassword,
            decoded.email,
        ]);

        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}}
