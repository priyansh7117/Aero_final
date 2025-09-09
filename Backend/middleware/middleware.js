const jwt = require('jsonwebtoken');
const User = require('../models/User');

async function authMiddleware(req, res, next){
  const header = req.headers.authorization;
  if(!header || !header.startsWith('Bearer ')) return res.status(401).json({ message: 'No token' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.id).select('-passwordHash');
    if(!user) return res.status(401).json({ message: 'Invalid token' });
    req.user = user;
    next();
  } catch(err){
    return res.status(401).json({ message: 'Invalid token' });
  }
}

module.exports = authMiddleware;
