const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
// nodemailer optional:
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  // configure if you want real email sending
  // host: process.env.EMAIL_HOST,
  // auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

router.post('/signup', async (req, res) => {
  try {
    const { username, mobile, email, password } = req.body;
    if(!username || !email || !password) return res.status(400).json({ message: 'Missing fields' });
    const existing = await User.findOne({ email });
    if(existing) return res.status(400).json({ message: 'Email already used' });
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = await User.create({ username, mobile, email, passwordHash: hash });
    // create verification token
    const verificationToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn:'2d' });

    // Optionally send email here with verification link (uncomment and configure transporter)
    // const verifyUrl = `${process.env.FRONTEND_URL}/verify.html?token=${verificationToken}`;
    // await transporter.sendMail({
    //   to: user.email, from: process.env.EMAIL_USER,
    //   subject: 'Verify your Aero account',
    //   text: `Click to verify: ${verifyUrl}`
    // });

    // For dev convenience return the token (so UI can test verification)
    return res.json({ message: 'created', verificationToken });
  } catch(err){
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

router.post('/verify', async (req, res) => {
  try {
    const { token } = req.body;
    if(!token) return res.status(400).json({ message: 'No token' });
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.id);
    if(!user) return res.status(400).json({ message: 'Invalid token' });
    user.isVerified = true;
    await user.save();
    return res.json({ message: 'verified' });
  } catch(err){
    console.error(err);
    return res.status(400).json({ message: 'Invalid or expired token' });
  }
});

router.post('/resend', async (req, res) => {
  try {
    const { email } = req.body;
    if(!email) return res.status(400).json({ message: 'No email' });
    const user = await User.findOne({ email });
    if(!user) return res.status(404).json({ message: 'User not found' });
    if(user.isVerified) return res.status(400).json({ message: 'Already verified' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn:'2d' });
    // send email logic would go here
    return res.json({ message: 'resent', verificationToken: token });
  } catch(err){
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if(!email || !password) return res.status(400).json({ message: 'Missing fields' });
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ message: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(400).json({ message: 'Invalid credentials' });
    if(!user.isVerified) return res.status(403).json({ message: 'Email not verified' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn:'7d' });
    return res.json({ token, user: { username: user.username, email: user.email, mobile: user.mobile } });
  } catch(err){
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

const authMiddleware = require('../middleware/authMiddleware');

router.get('/me', authMiddleware, async (req, res) => {
  // req.user is set by middleware
  const user = req.user.toObject();
  delete user.passwordHash;
  res.json(user);
});

router.post('/profile', authMiddleware, async (req, res) => {
  try {
    const { username, mobile, diseases, aqiAlertThreshold } = req.body;
    const u = req.user;
    if(username) u.username = username;
    if(mobile) u.mobile = mobile;
    if(Array.isArray(diseases)) u.diseases = diseases;
    if(typeof aqiAlertThreshold !== 'undefined') u.aqiAlertThreshold = aqiAlertThreshold;
    await u.save();
    res.json({ message: 'updated' });
  } catch(err){
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
