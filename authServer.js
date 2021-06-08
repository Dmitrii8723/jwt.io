const express = require('express');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(express.json());

let refreshTokens = [];

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

app.post('/login', (req, res) => {
const { username } = req.body; 
    const user = { name: username };
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
}

app.listen(4000);