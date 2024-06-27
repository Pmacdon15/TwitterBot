import OAuth from 'oauth-1.0a';
import got from 'got';
import qs from 'querystring';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { createInterface } from 'readline';

dotenv.config();
const consumer_key = process.env.CONSUMER_KEY;
const consumer_secret = process.env.CONSUMER_SECRET;

const readline = createInterface({
    input: process.stdin,
    output: process.stdout
});

const endpointURL = `https://api.twitter.com/2/tweets`;
// this example uses PIN-based OAuth to authorize the user
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

export async function input(prompt) {
    return new Promise(async (resolve, reject) => {
        readline.question(prompt, (out) => {
            readline.close();
            resolve(out);
        });
    });
}

export async function requestToken() {
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


export async function accessToken({
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


export async function getRequest(oAuthAccessToken, text) {
    try {
        const token = {
            key: oAuthAccessToken.oauth_token,
            secret: oAuthAccessToken.oauth_token_secret
        };

        // Generate Authorization header using stored tokens
        const authHeader = oauth.toHeader(oauth.authorize({
            url: endpointURL,
            method: 'POST'
        }, token));

        const req = await got.post(endpointURL, {
            json: { text },
            responseType: 'json',
            headers: {
                Authorization: authHeader["Authorization"],
                'user-agent': "v2CreateTweetJS",
                'content-type': "application/json",
                'accept': "application/json"
            }
        });

        return req.body;
    } catch (error) {
        throw error;
    }
}
