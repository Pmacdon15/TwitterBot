import express from 'express';
import bodyParser from 'body-parser';
import OAuth from 'oauth-1.0a';
// import crypto from 'crypto';
// import qs from 'querystring';
import { requestToken, accessToken, input, getRequest } from './functions.js';

const app = express();

// Parse JSON bodies for this app
app.use(bodyParser.json());

const requestTokenURL = 'https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write';
const authorizeURL = new URL('https://api.twitter.com/oauth/authorize');
const accessTokenURL = 'https://api.twitter.com/oauth/access_token';

const consumer_key = process.env.CONSUMER_KEY;
const consumer_secret = process.env.CONSUMER_SECRET;

const oauth = OAuth({
  consumer: {
    key: consumer_key,
    secret: consumer_secret
  },
  signature_method: 'HMAC-SHA1',
  hash_function: (baseString, key) => crypto.createHmac('sha1', key).update(baseString).digest('base64')
});

let oAuthAccessToken;
let oAuthRequestToken;

app.post('/post', async (req, res) => {
  try {
    const { text } = req.body;
    const response = await getRequest(oAuthAccessToken, text);
    console.dir(response, { depth: null });
    res.json(response); // Assuming getRequest returns JSON response from Twitter API
  } catch (error) {
    console.log("Error: ", error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(3000, async () => {
  console.log('Server listening on port 3000');
  try {
    oAuthRequestToken = await requestToken();
    authorizeURL.searchParams.append('oauth_token', oAuthRequestToken.oauth_token);
    console.log('Please go here and authorize:', authorizeURL.href);
    const pin = await input('Paste the PIN here: ');
    oAuthAccessToken = await accessToken(oAuthRequestToken, pin.trim());
    console.log('Access Token:', oAuthAccessToken); // Verify if access token is obtained
  } catch (error) {
    console.log("Error: ", error);
  }
});
