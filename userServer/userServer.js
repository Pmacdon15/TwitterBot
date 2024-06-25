import express from 'express';
const app = express();
import { requestToken,  accessToken , input} from './functions.js'
import { createInterface } from 'readline';
//import { question, close } from 'readline';
import dotenv from 'dotenv';
import OAuth from 'oauth-1.0a';

let oAuthAccessToken
let oAuthRequestToken

const requestTokenURL = 'https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write';
const authorizeURL = new URL('https://api.twitter.com/oauth/authorize');
const accessTokenURL = 'https://api.twitter.com/oauth/access_token';

const readline = createInterface({
    input: process.stdin,
    output: process.stdout
});

dotenv.config();

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



app.listen(3000, async () => {
  console.log('Server listening on port 6969');
  try {
    // Get request token
    oAuthRequestToken = await requestToken();
    // Get authorization
    authorizeURL.searchParams.append('oauth_token', oAuthRequestToken.oauth_token);
    console.log('Please go here and authorize:', authorizeURL.href);
    const pin = await input('Paste the PIN here: ');
    // Get the access token
    oAuthAccessToken = await accessToken(oAuthRequestToken, pin.trim());
  } catch (error) {
    console.log("Error: ", error);
  }
});