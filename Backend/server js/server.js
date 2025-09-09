require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://127.0.0.1:5500'
}));

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser:true, useUnifiedTopology:true
}).then(()=> {
  console.log('Mongo connected');
  app.listen(PORT, ()=> console.log('Server running on port', PORT));
}).catch(err=>{
  console.error('DB connect error', err);
});
