const express = require('express');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcrypt');

const app = express();

app.use(express.json());

let refreshTokens = [];

let users = [];

const posts = [
    {
        username: 'Dmitrii',
        title: 'Post 1'
    },
    {
        username: 'Kyle',
        title: 'Post 2'
    }
]

app.post('/users', async (req, res) => {
    try {
const hash = await bcrypt.hash(req.body.password, 10);
const user = { 
    name: req.body.name, 
    password: hash
};
users.push(user);
res.sendStatus(201)
    } catch {
res.sendStatus(500)
    }
});

app.get('/users', (req, res) => {
    res.status(200).send(users);
})

app.get('/posts', authenticateToken, (req, res) => {
res.json(posts.filter((post) => post.username === req.user.name));
});

// Routes related to authantication
app.delete('/logout', (req, res) => {
refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
res.sendStatus(204);
});

app.post('/token', (req, res) => {
const refreshToken = req.body.token;
if (refreshToken === null) return res.sendStatus(401);
if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
  if (err) return res.sendStatus(403);
const accessToken = generateAccessToken({ name: user.name });
res.json({ accessToken });
});
});

app.post('/users/login', async (req, res) => {
  const user = users.find(user => user.name === req.body.username);
  if (user === null) {
      return res.status(400).send('Cannot find user');
  } 
  try {
  if(await bcrypt.compare(req.body.password, user.password)) {
  const accessToken = generateAccessToken({ name: user.name });
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
  } else {
   res.status(401).send('Not Allowed');
  }
} catch {
    res.sendStatus(500);
}
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === null) return res.sendStatus(401);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
    }

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
}

app.listen(3000);