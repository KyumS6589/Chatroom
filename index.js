const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const Joi = require('joi');
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';
const DB_PATH = process.env.DB_PATH || './data/chat.db';

if (!fs.existsSync('./data')) fs.mkdirSync('./data');
const db = new Database(DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
);
CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS memberships (
  user_id INT,
  room_id INT,
  UNIQUE(user_id, room_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INT,
  user_id INT,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

app.use(express.json());
app.use(helmet());
app.use(morgan('dev'));

const limiter = rateLimit({ windowMs: 60*1000, max: 100 });
app.use(limiter);

function auth(req,res,next){
  const header=req.headers['authorization'];
  if(!header) return res.status(401).json({error:'Missing token'});
  const token=header.split(' ')[1];
  try{
    req.user=jwt.verify(token,JWT_SECRET);
    next();
  }catch(e){ res.status(403).json({error:'Invalid token'}); }
}

app.post('/api/auth/signup', async (req,res)=>{
  const {username,password}=req.body;
  if(!username||!password) return res.status(400).json({error:'Missing fields'});
  const hash=await bcrypt.hash(password,10);
  try{
    const stmt=db.prepare('INSERT INTO users (username,password) VALUES (?,?)');
    const info=stmt.run(username,hash);
    const token=jwt.sign({id:info.lastInsertRowid,username},JWT_SECRET);
    res.json({token});
  }catch(e){ res.status(400).json({error:'Username already exists'}); }
});

app.post('/api/auth/login', async (req,res)=>{
  const {username,password}=req.body;
  const user=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!user) return res.status(400).json({error:'Invalid credentials'});
  const match=await bcrypt.compare(password,user.password);
  if(!match) return res.status(400).json({error:'Invalid credentials'});
  const token=jwt.sign({id:user.id,username},JWT_SECRET);
  res.json({token});
});

app.get('/api/rooms', auth, (req,res)=>{
  const rooms=db.prepare('SELECT * FROM rooms').all();
  res.json({rooms});
});

app.post('/api/rooms', auth, (req,res)=>{
  const {name}=req.body;
  if(!name) return res.status(400).json({error:'Missing room name'});
  try{
    const stmt=db.prepare('INSERT INTO rooms (name) VALUES (?)');
    const info=stmt.run(name);
    res.json({id:info.lastInsertRowid,name});
  }catch(e){ res.status(400).json({error:'Room already exists'}); }
});

app.post('/api/rooms/:id/join', auth, (req,res)=>{
  const roomId=req.params.id;
  try{
    db.prepare('INSERT OR IGNORE INTO memberships (user_id,room_id) VALUES (?,?)').run(req.user.id,roomId);
    res.json({joined:true});
  }catch(e){ res.status(400).json({error:'Cannot join room'}); }
});

app.post('/api/rooms/:id/messages', auth, (req,res)=>{
  const {content}=req.body;
  if(!content) return res.status(400).json({error:'Missing message'});
  db.prepare('INSERT INTO messages (room_id,user_id,content) VALUES (?,?,?)').run(req.params.id,req.user.id,content);
  res.json({sent:true});
});

app.get('/api/rooms/:id/messages', auth, (req,res)=>{
  const limit=parseInt(req.query.limit)||50;
  const offset=parseInt(req.query.offset)||0;
  const rows=db.prepare(`
    SELECT m.id,m.content,m.created_at,u.username
    FROM messages m JOIN users u ON m.user_id=u.id
    WHERE m.room_id=?
    ORDER BY m.created_at DESC
    LIMIT ? OFFSET ?
  `).all(req.params.id,limit,offset);
  res.json({messages:rows});
});

app.listen(PORT,()=>console.log('Server running on port',PORT));
