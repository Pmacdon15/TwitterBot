import express from 'express';
const app = express();
import OAuth from 'oauth-1.0a';
import got from 'got';
import qs from 'querystring';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

const consumer_key = process.env.CONSUMER_KEY;
const consumer_secret = process.env.CONSUMER_SECRET;

const requestTokenURL = 'https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write';
const authorizeURL = new URL('https://api.twitter.com/oauth/authorize');
const accessTokenURL = 'https://api.twitter.com/oauth/access_token';

const oauth = OAuth({
  consumer: {
    key: consumer_key,
    secret: consumer_secret
  },
  signature_method: 'HMAC-SHA1',
  hash_function: (baseString, key) => crypto.createHmac('sha1', key).update(baseString).digest('base64')
});

let token = null;

async function requestToken() {
  const authHeader = oauth.toHeader(oauth.authorize({
    url: requestTokenURL,
    method: 'POST'
  }));

  const req = await got.post(requestTokenURL, {
    headers: {
      Authorization: authHeader["Authorization"]
    }
  });
  if (req.body) {
    return qs.parse(req.body);
  } else {
    throw new Error('Cannot get an OAuth request token');
  }
}

async function accessToken({
  oauth_token,
  oauth_token_secret
}, verifier) {
  const authHeader = oauth.toHeader(oauth.authorize({
    url: accessTokenURL,
    method: 'POST'
  }));
  const path = `https://api.twitter.com/oauth/access_token?oauth_verifier=${verifier}&oauth_token=${oauth_token}`
  const req = await got.post(path, {
    headers: {
      Authorization: authHeader["Authorization"]
    }
  });
  if (req.body) {
    return qs.parse(req.body);
  } else {
    throw new Error('Cannot get an OAuth request token');
  }
}

app.get('/login', async (req, res) => {
    try {
      const oAuthRequestToken = await requestToken();
      const url = `${authorizeURL.href}?oauth_token=${oAuthRequestToken.oauth_token}`;
      console.log(`Please go here and authorize: ${url}`);
      res.redirect('/callback?oauth_token=' + oAuthRequestToken.oauth_token);
    } catch (e) {
      console.error(e);
      res.status(500).send('Error during login');
    }
  });
  app.get('/callback', async (req, res) => {
    const oAuthRequestToken = req.query.oauth_token;
    console.log('Enter PIN: ');
    const pin = await input('');
    try {
      const oAuthAccessToken = await accessToken(oAuthRequestToken, pin);
      token = oAuthAccessToken;
      console.log('Logged in successfully!');
      res.send('Logged in successfully!');
    } catch (e) {
      console.error(e);
      res.status(500).send('Error during callback');
    }
  });
  
  async function input(prompt) {
    return new Promise(async (resolve, reject) => {
      const readline = require('readline');
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });
      rl.question(prompt, (pin) => {
        rl.close();
        resolve(pin);
      });
    });
  }

app.post('/tweet', async (req, res) => {
  if (!token) {
    return res.status(401).send('Login required');
  }
  const data = req.body;
  const response = await getRequest(token, data);
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server listening on port 3000');
});