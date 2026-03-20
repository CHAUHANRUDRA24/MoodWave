const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const https = require('https');
const querystring = require('querystring');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'Rs7YILgmoWlLMoOK33gzDqcZUgT3RBw6HrQiRyHzYsz';

// Middleware
app.use(cors());
app.use(express.json());

// ─── SPOTIFY CREDENTIALS ─────────────────────────────────────────────────────
const SPOTIFY_CLIENT_ID     = process.env.SPOTIFY_CLIENT_ID || 'ca3b53950d104ceeade097021440634b';
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || 'aa484d2ea2e841b7b88f48ef1e1cb27e';
const SPOTIFY_REDIRECT_URI  = process.env.REDIRECT_URI || 'https://mood-wave-zeta.vercel.app/callback';
const SPOTIFY_SCOPES        = 'user-read-private user-read-email user-top-read user-library-read user-library-modify playlist-read-private playlist-read-collaborative user-read-playback-state user-modify-playback-state';

// ─── CLIENT CREDENTIALS TOKEN (for anonymous search / featured playlists) ────
let appAccessToken = '';
let appTokenExpiry = 0;

async function getAppToken() {
    if (appAccessToken && Date.now() < appTokenExpiry) return appAccessToken;

    const auth = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
    const data = querystring.stringify({ grant_type: 'client_credentials' });

    return new Promise((resolve, reject) => {
        const req = https.request({
            hostname: 'accounts.spotify.com',
            path: '/api/token',
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(data)
            }
        }, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                const r = JSON.parse(body);
                appAccessToken = r.access_token;
                appTokenExpiry = Date.now() + r.expires_in * 1000 - 60000;
                resolve(appAccessToken);
            });
        });
        req.on('error', reject);
        req.write(data);
        req.end();
    });
}

// ─── USER SESSION HELPERS (JWT based to work on serverless) ─────────────────
function signSession(data) {
    return jwt.sign(data, JWT_SECRET, { expiresIn: '1h' });
}

function verifySession(token) {
    try { return jwt.verify(token, JWT_SECRET); }
    catch(e) { return null; }
}

function makeSpotifyRequest(path, token, method = 'GET', body = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.spotify.com',
            path,
            method,
            headers: { 
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let resBody = '';
            res.on('data', c => resBody += c);
            res.on('end', () => {
                if (res.statusCode === 204) return resolve({ success: true });
                try { resolve(JSON.parse(resBody)); }
                catch(e) { resolve({ error: 'Parse error', body: resBody }); }
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

// ─── OAUTH 2.0 LOGIN ─────────────────────────────────────────────────────────
app.get('/api/spotify/login', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const authUrl = 'https://accounts.spotify.com/authorize?' +
        querystring.stringify({
            client_id:     SPOTIFY_CLIENT_ID,
            response_type: 'code',
            redirect_uri:  SPOTIFY_REDIRECT_URI,
            scope:         SPOTIFY_SCOPES,
            state
        });
    res.redirect(authUrl);
});

// ─── OAUTH 2.0 CALLBACK ───────────────────────────────────────────────────────
app.get('/callback', async (req, res) => {
    const { code, error } = req.query;
    if (error) return res.redirect(`/spotify.html?error=${encodeURIComponent(error)}`);

    const auth = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
    const body = querystring.stringify({
        grant_type:   'authorization_code',
        code,
        redirect_uri: SPOTIFY_REDIRECT_URI
    });

    const tokenData = await new Promise((resolve, reject) => {
        const reqT = https.request({
            hostname: 'accounts.spotify.com',
            path: '/api/token',
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type':  'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(body)
            }
        }, (r) => {
            let d = '';
            r.on('data', c => d += c);
            r.on('end', () => resolve(JSON.parse(d)));
        });
        reqT.on('error', reject);
        reqT.write(body);
        reqT.end();
    });

    if (!tokenData.access_token) {
        return res.redirect('/spotify.html?error=token_exchange_failed');
    }

    const sessionId = signSession({
        accessToken:  tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        expiresAt:    Date.now() + tokenData.expires_in * 1000 - 60000
    });

    res.redirect(`/spotify.html?session=${sessionId}`);
});

// ─── REFRESH TOKEN ─────────────────────────────────────────────────────────────
async function refreshUserToken(refreshToken) {
    if (!refreshToken) return null;

    const auth = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
    const body = querystring.stringify({ grant_type: 'refresh_token', refresh_token: refreshToken });

    try {
        const data = await new Promise((resolve, reject) => {
            const req = https.request({
                hostname: 'accounts.spotify.com',
                path: '/api/token',
                method: 'POST',
                headers: {
                    'Authorization': `Basic ${auth}`,
                    'Content-Type':  'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(body)
                }
            }, (r) => {
                let d = '';
                r.on('data', c => d += c);
                r.on('end', () => resolve(JSON.parse(d)));
            });
            req.on('error', reject);
            req.write(body);
            req.end();
        });

        if (data.access_token) {
            return {
                accessToken: data.access_token,
                expiresAt:   Date.now() + data.expires_in * 1000 - 60000
            };
        }
    } catch(e) { console.error('Refresh fail:', e); }
    return null;
}

async function getValidUserToken(session) {
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        const refreshed = await refreshUserToken(session.refreshToken);
        if (refreshed) {
            session.accessToken = refreshed.accessToken;
            session.expiresAt   = refreshed.expiresAt;
            // Note: In serverless we can't update original 'session' effectively 
            // but the client will get failure if it's too old and must relogin.
            // For now, this temporary session object will work for the lifetime of the request.
        }
    }
    return session.accessToken;
}

// ─── SESSION VALIDATION MIDDLEWARE ────────────────────────────────────────────
async function requireUserSession(req, res, next) {
    const sessionId = req.query.session || req.headers['x-session-id'];
    const session = verifySession(sessionId);
    if (!session) {
        return res.status(401).json({ error: 'No valid session. Please login with Spotify.' });
    }
    req.userToken = await getValidUserToken(session);
    req.sessionId = sessionId;
    next();
}

// ─── USER SPOTIFY ENDPOINTS ────────────────────────────────────────────────────
app.get('/api/spotify/me', requireUserSession, async (req, res) => {
    try {
        const data = await makeSpotifyRequest('/v1/me', req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/top-tracks', requireUserSession, async (req, res) => {
    try {
        const limit = req.query.limit || 20;
        const time_range = req.query.time_range || 'medium_term';
        const data = await makeSpotifyRequest(`/v1/me/top/tracks?limit=${limit}&time_range=${time_range}`, req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/top-artists', requireUserSession, async (req, res) => {
    try {
        const data = await makeSpotifyRequest('/v1/me/top/artists?limit=10', req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/recently-played', requireUserSession, async (req, res) => {
    try {
        const data = await makeSpotifyRequest('/v1/me/player/recently-played?limit=20', req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/user-search', requireUserSession, async (req, res) => {
    try {
        const { q, type = 'track' } = req.query;
        const data = await makeSpotifyRequest(`/v1/search?q=${encodeURIComponent(q)}&type=${type}&limit=20`, req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/liked-songs', requireUserSession, async (req, res) => {
    try {
        const limit = req.query.limit || 20;
        const offset = req.query.offset || 0;
        const data = await makeSpotifyRequest(`/v1/me/tracks?limit=${limit}&offset=${offset}`, req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/check-liked', requireUserSession, async (req, res) => {
    try {
        const { ids } = req.query; // Comma separated IDs
        const data = await makeSpotifyRequest(`/v1/me/tracks/contains?ids=${ids}`, req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/spotify/like-song', requireUserSession, async (req, res) => {
    try {
        const { ids } = req.body; // Array of IDs
        const data = await makeSpotifyRequest(`/v1/me/tracks?ids=${ids.join(',')}`, req.userToken, 'PUT');
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/spotify/unlike-song', requireUserSession, async (req, res) => {
    try {
        const { ids } = req.body; // Array of IDs
        const data = await makeSpotifyRequest(`/v1/me/tracks?ids=${ids.join(',')}`, req.userToken, 'DELETE');
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/spotify/playlists', requireUserSession, async (req, res) => {
    try {
        const data = await makeSpotifyRequest('/v1/me/playlists?limit=20', req.userToken);
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});


// Serve the static HTML page from the root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve the Spotify integration page
app.get('/spotify.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'spotify.html'));
});

// Serve the Moods page
app.get('/moods.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'moods.html'));
});

// Serve the Playlists page
app.get('/playlists.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'playlists.html'));
});

// Serve the Library page
app.get('/library.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'library.html'));
});

// Serve the Dashboard page
app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Spotify API Proxy Endpoints (App/Anonymous token)
app.get('/api/spotify/search', async (req, res) => {
    try {
        const { q, type } = req.query;
        const token = await getAppToken();
        const spotifyRes = await makeSpotifyRequest(`/v1/search?q=${encodeURIComponent(q)}&type=${type || 'track'}&limit=20`, token);
        res.json(spotifyRes);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/spotify/featured', async (req, res) => {
    try {
        const token = await getAppToken();
        const spotifyRes = await makeSpotifyRequest('/v1/browse/featured-playlists?limit=10', token);
        res.json(spotifyRes);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/spotify/playlist/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const token = await getAppToken();
        const spotifyRes = await makeSpotifyRequest(`/v1/playlists/${id}`, token);
        res.json(spotifyRes);
    } catch (error) { res.status(500).json({ error: error.message }); }
});


// Start the server
app.listen(PORT, () => {
    console.log(`MoodWave Server is running on http://localhost:${PORT}`);
    console.log(`Visit http://localhost:${PORT} to log in with Spotify.`);
});
