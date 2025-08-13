const google_userId = process.env.GOOGLE_USER_ID;
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "")
{
    console.log("info [game]: Error, no token is provide.");
    process.exit(1);
}
const jwt_secret = process.env.JWT_SECRET;

const fastify = require('fastify')();
const crypto = require('crypto');
const Database = require('better-sqlite3');
const fs = require('fs');
const multipart = require('@fastify/multipart');
const { pipeline } = require('node:stream/promises');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');
const googleClient = new OAuth2Client(google_userId); //read from .env
fastify.register(multipart);

//-------------secu------------------
const fastifyJwt = require('@fastify/jwt');
const fastifyCookie = require('@fastify/cookie');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const fastifyCors = require('@fastify/cors');
//-------------secu------------------


const database = new Database('./data/pongUser.db');

function generate_salt()
{
  return crypto.randomBytes(16).toString('hex');
}

function hash_pw(password, salt)
{
  const iterations = 100000;
  const keylen = 64;
  const digest = 'sha512';
  const saltstr = salt.toString();

  const hash = crypto.pbkdf2Sync(password, saltstr, iterations, keylen, digest);
  return hash.toString('hex');
}

try {
  database.exec(`
      CREATE TABLE IF NOT EXISTS ponguser(
        id  INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT,
        alias    TEXT,
        password TEXT,
        salt     TEXT,
        twofa_secret  TEXT,
        twofa_enabled INTEGER DEFAULT 0
      ) STRICT
  `);
}
catch(e)
{
  console.log("info [user]:", e);
}


const insert = database.prepare('INSERT INTO ponguser (username, alias, password, salt, twofa_secret, twofa_enabled) VALUES (?, ?, ?, ?, NULL, 0)');
const query_pw = database.prepare('SELECT password FROM ponguser WHERE username=?');
const query_salt = database.prepare('SELECT salt FROM ponguser WHERE username=?');
const query_alias = database.prepare('SELECT alias FROM ponguser WHERE username=?');
const query_username = database.prepare('SELECT username FROM ponguser WHERE username=?');
const query_userinfo = database.prepare('SELECT id, alias ,username FROM ponguser WHERE username=?');
const update_pw = database.prepare('UPDATE ponguser SET password=@password WHERE username=@username');
const update_alias = database.prepare('UPDATE ponguser SET alias=@alias WHERE username=@username');
const delete_user = database.prepare('DELETE FROM ponguser WHERE username=@username');

//------------------------------------------SW-------------------------------------------//
const query_alias_existence = database.prepare('SELECT alias FROM ponguser WHERE alias=?');
//------------------------------------------SW-------------------------------------------//

const query_userid_by_alias = database.prepare('SELECT id, alias FROM ponguser WHERE alias=?');////0707
const query_userid_by_username = database.prepare('SELECT id, alias FROM ponguser WHERE username=?');
const query_max_id = database.prepare('SELECT MAX(id) AS max_id FROM ponguser');

//-------------------------------------secu------------------------------
const query_2fasecret = database.prepare('SELECT twofa_secret FROM ponguser WHERE username=?');
const query_2fastatus = database.prepare('SELECT twofa_enabled FROM ponguser WHERE username=?');
const update_2fasecret = database.prepare('UPDATE ponguser SET twofa_secret = @secret WHERE username = @username');
const update_2fastatus = database.prepare('UPDATE ponguser SET twofa_enabled = 1 WHERE username = @username');
const disable_2fa = database.prepare('UPDATE ponguser SET twofa_secret = NULL, twofa_enabled = 0 WHERE username = @username');

fastify.register(fastifyCors, {
  origin: 'https://localhost:9000',
  credentials: true
});


fastify.register(fastifyJwt, {
  secret: jwt_secret,
  cookie: {
    cookieName: 'token',
    signed: false
  },
  token: (request) => {
    const auth = request.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) {
      return auth.slice(7);
    }
    if (request.cookies && request.cookies.token) {
      return request.cookies.token;
    }
    return null;
  }
});

fastify.register(fastifyCookie);

async function verifyToken(req, res) {
  try {
    await req.jwtVerify();
    return false;
  } catch (err) {
    console.log('info [user]: JWT verify failed.');
    res.code(401).send({ info: 'Invalid token', username: '', alias: '', state2fa: false });
    return true;
  }
}

authenticator.options = { issuer: 'Transcendence' };

fastify.get('/api/2fa/setup/:id', async (req, res) => {
  try {
    console.log("info [2FA]: Get request from", req.params.id);
    if (await verifyToken(req, res)) return;
    const userId = req.params.id;
    if (req.user.username !== userId) {
      res.code(403).send({ info: 'Forbidden' });
      return ;
    }
    const status = query_2fastatus.get(userId);
    if (status && status.twofa_enabled) {
      return res.code(400).send({ success: false, info: '2FA is already enabled' });
    }
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(userId, 'Transcendence', secret);
    update_2fasecret.run({ secret, username: userId });

    const qrImageUrl = await qrcode.toDataURL(otpauth);

    res.send({
      success: true,
      qrImageUrl       // base64 image
    });

  } catch (e) {
    console.log(e);
    res.code(400).send({ success: false, info: 'Failed to setup 2FA' });
  }
});

fastify.patch('/api/2fa/setup/:id', async (req, res) => {
  if (await verifyToken(req, res)) return;
  const userId = req.params.id;
  if (req.user.username !== userId) {
    res.code(403).send({ info: 'Forbidden' });
    return ;
  }
  const { token } = req.body;

  const row = query_2fasecret.get(userId);
  const status = query_2fastatus.get(userId);
  if (status && status.twofa_enabled) {
    return res.code(400).send({ success: false, info: '2FA is already enabled' });
  }

  if (!row || !row.twofa_secret) {
    return res.code(400).send({ success: false, info: '2FA not initialized' });
  }

  const isValid = authenticator.check(token, row.twofa_secret);

  if (!isValid) {
    return res.code(401).send({ success: false, info: 'Invalid 2FA token' });
  }

  update_2fastatus.run({ username: userId });

  res.code(200).send({ success: true, info: '2FA enabled successfully' });
});

fastify.post('/api/2fa/verify', async (req, res) => {
  try {
    const { username, token } = req.body;

    if (!username || !token) {
      return res.code(400).send({ evt: "login_state", success: false, info: 'Missing username or token' });
    }

    const row = query_2fasecret.get(username);
    const status = query_2fastatus.get(username);

    if (!row || !row.twofa_secret || !status || !status.twofa_enabled) {
      return res.code(400).send({ evt: "login_state", success: false, info: '2FA not enabled' });
    }

    const isValid = authenticator.check(token, row.twofa_secret);

    if (!isValid) {
      return res.code(401).send({ evt: "login_state", success: false, info: 'Invalid 2FA token' });
    }

    const jwtToken = fastify.jwt.sign(
      { username: username, alias: query_alias.get(username).alias },
      { expiresIn: '1h' }
    );

    res
      .setCookie('token', jwtToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 3600,
        path:'/api'
      })
      .code(200)
      .send({
        evt: "login_state",
        success: true,
        info: "Login success via 2FA"
      });

  } catch (e) {
    console.log(e);
    res.code(400).send({ success: false, info: 'Failed to verify 2FA' });
  }
});

fastify.delete('/api/2fa/setup/:id', async (req, res) => {
  if (await verifyToken(req, res)) return;
  const username = req.params.id;
  if (req.user.username !== username) {
    res.code(403).send({ info: 'Forbidden' });
    return ;
  }
  const { token } = req.body;

  const row = query_2fasecret.get(username);
  if (!row || !row.twofa_secret) {
    return res.code(400).send({ success: false, info: '2FA not enabled' });
  }

  const isValid = authenticator.check(token, row.twofa_secret);
  if (!isValid) {
    return res.code(401).send({ success: false, info: 'Invalid 2FA token' });
  }

  disable_2fa.run({ username });

  res.code(200).send({ success: true, info: '2FA disabled successfully' });
});
//-------------------------------------secu------------------------------

function show_user_db(database)
{
  const query = database.prepare('SELECT * FROM ponguser ORDER BY id');
  if (query)
    console.table(query.all());
}

function is_Valid_alias(alias)
{
  if (alias.length === 0 || alias.length > 10)
    return false;
  if (alias === "Deleted_user" || alias === "Invalid_alias" || alias === "default")
    return false;
  return /^[A-Za-z0-9_]+$/.test(alias);
}

function is_valid_password(password)
{
  if (password.length > 25 || password.length < 8)
    return false;

  const passwordRegex = /^[-A-Za-z0-9!@#$%^&*_+={}|:;<>,.?~]+$/;
  if (!passwordRegex.test(password))
      return false;

  const RegexNum = /[0-9]/;
  const RegexUpper = /[A-Z]/;
  const RegexLower = /[a-z]/;
  const RegexSpecial = /[-!@#$%^&*_+={}|:;<>,.?~]/;

  if (!RegexLower.test(password) || !RegexUpper.test(password)||!RegexNum.test(password)||!RegexSpecial.test(password))
    return false;

  return true;
}

function is_valid_email(email) {
  const emailRegex = /^[-a-zA-Z0-9._%+]+@[-a-zA-Z0-9.]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

async function downloadImage(url, path) {
  const response = await axios.get(url, { responseType: 'stream' });

  return new Promise((resolve, reject) => {
    const writer = fs.createWriteStream(path);
    response.data.pipe(writer);
    writer.on('finish', resolve);
    writer.on('error', reject);
  });
}


fastify.post('/api/users/', async (req, res) => {
  try {
    let avatarFile = null;
    let userdata = null;

    const parts = req.parts();
    for await (const part of parts) {
      if (part.type === 'file' && part.fieldname === 'avatar') {
        avatarFile = part;
        if (avatarFile) {
          
          const max_id = query_max_id.get();
          let num_user = max_id ? max_id.max_id + 1 : 1;

          const path = "./avatar/" + num_user + ".png";
          await pipeline(avatarFile.file, fs.createWriteStream(path));
        }
      }
      else if (part.type === 'field' && part.fieldname === 'userdata') {
        userdata = JSON.parse(part.value);
      }
    }

    if (!userdata) {
      const body = JSON.stringify({info: 'Error: Missing user data.'});
      res.code(400).send(body);
      console.log("info [user]: Error: Missing user data.");
      return;
    }

    if (userdata.alias === "AI_Bot" || userdata.alias === "default" || !is_Valid_alias(userdata.alias)) {
      const body = JSON.stringify({info: 'Error: Invalid user alias.'});
      res.code(400).send(body);
      console.log("info [user]: Error: Invalid user alias.");
      return;
    }

    if (!is_valid_password(userdata.password)) {
      const body = JSON.stringify({info: 'Error: Invalid user password, at least an upper case, a lower case, a digit, a special character, 8-25 characters.'});
      res.code(400).send(body);
      console.log("info [user]: Error: Invalid user password.");
      return;
    }

    if (!is_valid_email(userdata.username)) {
      const body = JSON.stringify({info: 'Error: Invalid user email.'});
      res.code(400).send(body);
      console.log("info [user]: Error: Invalid user email.");
      return;
    }

    if (query_username.get(userdata.username) != undefined) {
      console.log("info [user]: Error: user", userdata.username, "is already existed.");
      const body = JSON.stringify({info: 'Error: user already exists.'});
      res.code(409).send(body);
      return;
    }

    if (query_alias_existence.get(userdata.alias) != undefined) {
      console.log("info [user]: Error: alias", userdata.alias, "is already existed.");
      const body = JSON.stringify({info: 'Error: alias already exists.'});
      res.code(409).send(body);
      return;
    }

    const salt = generate_salt();
    
    insert.run(userdata.username, userdata.alias, hash_pw(userdata.password, salt), salt);

    console.log("info [user]: user", userdata.username, "is created at", req.headers['x-real-ip'], ".");

    res.code(200);
    const body = JSON.stringify({info: 'User created.'});
    res.send(body);

  } catch(e) {
    res.code(400);
    const body = JSON.stringify({info: 'Error: Fail to create user.'});
    res.send(body);
    console.log("info [user]:", e);
  }
});

fastify.get('/api/users/:id', async (req, res) =>{
  try
  {
    if (await verifyToken(req, res)) return;
    const userId = req.params.id;
    if (req.user.username !== userId) {
      res.code(403).send({ info: 'Forbidden' });
      return ;
    }

    const alias = query_alias.get(userId);
    const username = query_username.get(userId);
    if (alias == undefined || username == undefined)
    {
      const dataStr = {"info": "Error: user not exist.", success: false};
      const dataBack = JSON.stringify(dataStr);
      res.code(404).send(dataBack);
      return;
    }
    const userAlias = {"alias": alias.alias, "username": username.username, success: true};
    console.log("info [user]: user", userId, "info is requested at", req.headers['x-real-ip'], ".");
    const dataBack = JSON.stringify(userAlias);
    res.code(200).send(dataBack);
  }
  catch(e)
  {
    const dataStr = {"info": "Error: Failed to get user data.", success: false};
    const dataBack = JSON.stringify(dataStr);
    res.code(400).send(dataBack);
    console.log(e);
    return;
  }
});

async function brodcast_update_alias(alias_change, uri) {
  try {
    const res = await fetch(uri, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(alias_change),
    });

    if (!res.ok) {
      throw new Error("Error: wrong response from the other services");
    }
    const data = await res.json();
    console.log("info [user]:", data.info);
  }
  catch (e)
  {
    console.log("info [user]:", e);
  }
}


fastify.patch('/api/users/:id', async (req, res) => {
  if (await verifyToken(req, res)) return;
  const id = req.params.id;
  if (req.user.username !== id) {
    res.code(403).send({ info: 'Forbidden' });
    return ;
  }
  var info = '';
  try
  {
    const saltObj = query_salt.get(id);
    if (saltObj == undefined)
    {
      res.code(404);
      res.header('Content-Type', 'application/json');
      info = 'Error: user not exists.';
      console.log("info [user]: Error: user", id, "not existed.");
      body = JSON.stringify({info});
      res.send(body);
      return;
    }

    const salt = saltObj.salt;

    var pw_modified = "Not required";
    var alias_modified = "Not required";
    if ("alias" in req.body)
    {
      const alias_exist = query_alias_existence.get(req.body.alias);
      const curr_alias = query_alias.get(id);

      if (alias_exist != undefined && curr_alias.alias != req.body.alias)  // alias is used by other user
      {
        res.code(409);
        res.header('Content-Type', 'application/json');
        info = 'Conflict of alias, not modified.';
        body = JSON.stringify({info});
        res.send(body);
        console.log("info [user]: user", id, "is not modified at", req.headers['x-real-ip'], ".");
        alias_modified = "Not modified";
        return;
      }
      else
      {
        
        const old_alias = query_alias.get(id).alias;
        const new_alias = req.body.alias;

        if (req.body.alias === "AI_Bot" || req.body.alias === "default" || !is_Valid_alias(req.body.alias))
        {
          res.code(400);
          const body = JSON.stringify({info: 'Error: Invalid user alias.'});
          res.send(body);
          console.log("info [user]: Error: Invalid user alias.");
          return;
        }

        const alias_change = {old_alias: old_alias, new_alias: new_alias};

        update_alias.run({alias: req.body.alias, username: id});
        
        brodcast_update_alias(alias_change, "http://t_friend:9766/internal/api/update");
        brodcast_update_alias(alias_change, "http://t_record:9431/internal/api/update");
        brodcast_update_alias(alias_change, "http://t_broker:9899/internal/api/update");
        alias_modified = "Modified";
      }
      
      //-----------------------------------------------SW-----------------------------------------
    }
    if ("password" in req.body)
    {
      const new_hashed_pw = hash_pw(req.body.password, salt);

      if (!is_valid_password(req.body.password))
      {
        res.code(400);
        const body = JSON.stringify({info: 'Invalid user password, at least an upper case, a lower case, a digit, a special caracter, 8-25 caracters.'});
        res.send(body);
        console.log("info [user]: Error: Invalid user password.");
        return;
      }

      if (query_pw.get(id).password != new_hashed_pw)
      {
        update_pw.run({password: new_hashed_pw, username: id});
        pw_modified = "Modified";
      }
      else
      {
        pw_modified = "Not modified";
      }
    }
    
    ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////
    // show_user_db(database);
    ////////////////////////////////////////////////////visualize database in the background/////////////////////////////////

    if (pw_modified === "Modified" || alias_modified === "Modified")
    {
      res.code(200);
      info = 'User modified.';
      body = JSON.stringify({info});
      if (alias_modified === "Modified") {
        const token = fastify.jwt.sign(
          { username: id, alias: req.body.alias },
          { expiresIn: '1h'}
        );
        res
          .setCookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            maxAge: 3600,
            path:'/api'
          })
      }
      res.send(body);
      console.log("info [user]: user", id, "is modified at", req.headers['x-real-ip'], ".");
    }
    else
    {
      res.code(409).send({info: 'Nothing is modified.'});
      console.log("info [user]: user", id, "is not modified at", req.headers['x-real-ip'], ".");
    }
  }
  catch(e)
  {
    res.code(400).send({info: 'Fail to modify.'});
    console.log("info [user]:", e);
  }
});

fastify.delete('/api/users/:id', async (req, res) => {

  if (await verifyToken(req, res)) return;
  const username = req.params.id;
  if (req.user.username !== username) {
    res.code(403).send({ info: 'Forbidden' });
    return ;
  }

  const salt = query_salt.get(username);
  if (salt === undefined)
  {
    info = 'Error: User not exist.';
    body = JSON.stringify({info});
    res.code(404).send(body);
    console.log("info [user]: user", username, "not exist.");
    return;
  }

  try {
    const userId = query_userid_by_username.get(username);
    const avatarFilePath = "./avatar/" + userId.id + ".png";

    fs.unlink(avatarFilePath, async (err) => {
      if (err) {
        throw new Error("Cannot delete user avatar.");
      }
      console.log("info [user]: user", username , "avatar deleted.");
    });

    delete_user.run({username: username});
    res.code(200).send({info: 'User deleted.'});

    const alias_change = {old_alias: userId.alias, new_alias: "Deleted_user"};
    brodcast_update_alias(alias_change, "http://t_friend:9766/internal/api/update");
    brodcast_update_alias(alias_change, "http://t_record:9431/internal/api/update");
    brodcast_update_alias(alias_change, "http://t_broker:9899/internal/api/update");

    console.log("info [user]: user", username, "deleted.");
  }
  catch (err)
  {
    res.code(400).send({info: 'Error: cannot delete.'});
    console.log("info [user]: Error: server error.", err);
  }
});

fastify.post('/api/logout', (req, res) => {
  res
    .clearCookie('token', {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path:'/api'
    })
    .code(200).send({ info: 'Logged out' });
});

fastify.post('/api/auth', (req, res) => {
  try{
    const salt = query_salt.get(req.body.username);
    if (!salt)
    {
      res.code(404);
      var dataReturn = {
            evt: "login_state",
            success: false,
            info: "User not exist."
      };
      res.send(dataReturn);
      return;
    }

    const true_pw_hash = query_pw.get(req.body.username).password;
    const pw_hash = hash_pw(req.body.password, salt.salt);

    if (pw_hash === true_pw_hash)
    {
      const status = query_2fastatus.get(req.body.username);
      if (status && status.twofa_enabled) {
        return res.code(206).send({
          evt: "login_state",
          success: false,
          info: "2FA required",
          require2FA: true
        });
      }
      const token = fastify.jwt.sign(
        { username: req.body.username, alias: query_alias.get(req.body.username).alias },
        { expiresIn: '1h'}
      );
      console.log("info [auth]: user", req.body.username, "logged in at", req.headers['x-real-ip']);
      res
        .setCookie('token', token, {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          maxAge: 3600,
          path:'/api'
        })
        .code(200)
        .send({
          evt: "login_state",
          success: true,
          info: "Login success."
        });
    }
    else
    {
      console.log("info [auth]: user:" , req.body.username , "at log in failed at", req.headers['x-real-ip']);
      var dataReturn = {
          evt: "login_state",
          success: false,
          info: "Login fail."
      };
      res.code(403).send(dataReturn);
    }
  }
  catch (err)
  {
    var dataReturn = {
          evt: "login_state",
          success: false,
          info: "Server error."
      };
    res.code(400).send(dataReturn);
    console.log("info [auth]: Error: wrong form data", err);
  }
});

fastify.get('/api/me', async (req, res) => {
  try {
    if (await verifyToken(req, res)) return;
    const username = req.user.username;
    const aliasRow = query_alias.get(username);
    const state2fa = query_2fastatus.get(username);
    if (!aliasRow || !state2fa) {
      return res.code(404).send({ success: false, info: 'User not found' });
    }

    // //---------------------------debug------------------------
    // show_user_db(database);
    // //---------------------------debug------------------------

    res.send({
      username: username,
      alias: aliasRow.alias ?? aliasRow,
      twofa_enabled: !!state2fa.twofa_enabled,
    });
  } catch (err) {
    res.code(401).send({ success: false, info: 'Unauthorized' });
    console.log("info [user]: Error:", err);
  }
});

async function verify_Gtoken(token) {
  try{
    if (!google_userId)
    {
      console.log("info [auth]: No google user id.");
      return (null);
    }
    
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: google_userId,
    });
    const payload = ticket.getPayload();
    return payload;
  }
  catch (e)
  {
    console.log("info [user]:", e);
    return (null);
  }
}

function generateTempAlias(){
  let i = 0;

  while (true)
  {
    if (query_alias_existence.get("Google_user_" + i.toString()))
      i++;
    else 
      return "Google_user_" + i.toString();
  }
  return "Invalid_alias";
}

fastify.post('/api/auth/google', async (req, res) => {
  try{

    const resJson = JSON.parse(req.body);

    const result = await verify_Gtoken(resJson.token);
    if (!result)
    {
      throw new Error("Google verify token failed");
    }

    //-----------------------------------------
    const salt = query_salt.get(result.email);
    if (!salt)
    {
      console.log("info [user]: User not exist, create new user for", result.email);

      const new_salt = generate_salt();

      let final_alias = result.given_name;

      if (query_alias_existence.get(final_alias) || !is_Valid_alias(final_alias)) //alias exist
      {
        final_alias = generateTempAlias();
        console.log("info [user]: Google account", result.email, "has conflict of alias, a random alias is assigned:", final_alias);  
      }

      const max_id = query_max_id.get();
      let num_user = max_id ? max_id.max_id + 1 : 1;

      insert.run(result.email, final_alias, null, new_salt);
      await downloadImage(result.picture, './avatar/' + num_user + '.png');

      const jwtToken = fastify.jwt.sign(
        { username: result.email, alias: query_alias.get(result.email).alias },
        { expiresIn: '1h' }
      );

      var dataReturn = {
          evt: "login_state_google",
          success: true,
          info: "Login success.",
          username: result.email,
          alias: final_alias,
      };
      res
        .setCookie('token', jwtToken, {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          maxAge: 3600,
          path:'/api'
        })
        .code(200).send(dataReturn);
      
      // show_user_db(database);
      return;
    }
    else 
    {
      console.log("info [user]: User exist, bind user for", result.email);

      const jwtToken = fastify.jwt.sign(
        { username: result.email, alias: query_alias.get(result.email).alias },
        { expiresIn: '1h' }
      );

      const userinfo = query_userinfo.get(result.email);

      var dataReturn = {
          evt: "login_state_google",
          success: true,
          info: "Login success.",
          username: result.email,
          alias: userinfo.alias,
      };
      res
        .setCookie('token', jwtToken, {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          maxAge: 3600,
          path:'/api'
        })
        .code(200).send(dataReturn);
      return;
    }
  }
  catch (e)
  {
    var dataReturn = {
          evt: "login_state",
          success: false,
          info: "Cannot login with your google account."
      };
    res.code(400).send(dataReturn);
    console.log("info [auth]: Error: error from Google auth", e);
  }
});


fastify.get('/internal/api/users/:alias', (req, res) =>{
  try
  {
    const userinfo = query_userid_by_alias.get(req.params.alias);
    if (userinfo == undefined)
    {
      res.code(404).send({"info": "Error: user not exist.", success: false});
      return;
    }
    console.log("info [user]: user", userinfo.alias, "info is requested internally.");
    res.code(200).send({"alias": userinfo.alias, "userid": userinfo.id, success: true});
  }
  catch(e)
  {
    res.code(400).send({"info": "Error: server error.", success: false});
    console.log(e);
    return;
  }
});

// //----------------------------------------------handle avatar---------------------//
fastify.get('/api/avatar/:id', (req, res) => {
  try
  {
    const alias = req.params.id;

    if (alias === "AI_Bot")
    {
      fs.readFile('./avatar/AI_Bot.png', (err, data) => {
        if (err)
        {
          if (err.code != 'ENOENT')
          {
            res.code(400).send({"info": "Error while reading avatar."});
            console.log("info [user]: Error: user", userId.alias, "avatar is opened with error.");
            return;
          }
          else
          {
            res.code(404).send({"info": "Can't found avatar."});
            console.log("info [user]: Error: user", userId.alias, "avatar is opened with error.");
            return;
          }
        }
        else 
        {
          console.log("info [user]: AI_Bot's avatar is requested at", req.headers['x-real-ip'], ".");
          res.header('Content-Type', 'image/png');
          res.header('Cache-Control', 'no-store');
          res.header('Pragma', 'no-cache');
          res.code(200).send(data);
          return;
        }
      });
    }

    const userId = query_userid_by_alias.get(alias);
    if (userId === undefined)
    {
      fs.readFile('./avatar/nouser.png', (err, data) => {
        if (err)
        {
          if (err.code != 'ENOENT')
          {
            res.code(400).send({"info": "Error while reading avatar."});
            console.log("info [user]: Error: user", userId.alias, "avatar is opened with error.");
            return;
          }
          else
          {
            res.code(404).send({"info": "Can't found avatar."});
            console.log("info [user]: Error: user", userId.alias, "avatar is opened with error.");
            return;
          }
        }
        else 
        {
          console.log("info [user]: deleted user's avatar is requested at", req.headers['x-real-ip'], ".");
          res.header('Content-Type', 'image/png');
          res.header('Cache-Control', 'no-store');
          res.header('Pragma', 'no-cache');
          res.code(200).send(data);
          
          return;
        }
      });
      return;
    }
    const imagePath = './avatar/' + userId.id + '.png';

    fs.readFile(imagePath, (err, data) => {
      if (err)
      {
        if (err.code != 'ENOENT')
        {
          res.code(400).send({"info": "Error while reading avatar."});
          console.log("info [user]: Error: user with alias", userId.alias, "avatar is opened with error.");
          return;
        }
        else
        {
          fs.readFile('./avatar/default.png', (err2, data2) =>{
            if (err2)
            {
              if (err2.code != 'ENOENT')
              {
                res.code(400).send({"info": "Error while reading avatar."});
                console.log("info [user]: Error: user", userId.alias, "avatar is opened with error.");
                return;
              }
              else
              {
                res.code(404).send({"info": "Can't found avatar."});
                console.log("info [user]: Error: user", userId.alias, "avatar is opened with error.");
                return;
              }
            }
            else
            {
              console.log("info [user]: default avatar is requested at", req.headers['x-real-ip'], ".");
              res.header('Cache-Control', 'no-store');
              res.header('Pragma', 'no-cache');
              res.header('Content-Type', 'image/png');
              res.code(200).send(data2);
              return;
            }
          });
        }
      }
      else
      {
        console.log("info [user]: user", userId.alias, "avatar is requested at", req.headers['x-real-ip'], ".");
        res.header('Cache-Control', 'no-store');
        res.header('Pragma', 'no-cache');
        res.header('Content-Type','image/png');
        res.code(200).send(data);
        return;
      }
    });
  }
  catch(e)
  {
    const dataStr = {"info": "Error to get avatar.", success: false};
    const dataBack = JSON.stringify(dataStr);
    res.code(400).send(dataBack);
    console.log(e);
    return;
  }
});
//----------------------------------------------handle avatar---------------------


//------------------------------------------------------------add test user----------------------

function add_test_user(username, password, alias)
{
  if (query_userid_by_alias.get(alias) || query_userid_by_username.get(username))
    return;

  salt = generate_salt();
  pw = hash_pw(password, salt);
  insert.run(username, alias, pw, salt);
}

const testAccount = process.env.TEST_ACCOUNTS;

if (testAccount)
{
  try{
    const accounts = JSON.parse(testAccount);

    for (const account of accounts)
    {
      add_test_user(account.username, account.password, account.alias);
    }
  }
  catch(e)
  {
    console.log("info [user]: Error: failed parse test account in ENV", e);
  }
}
//------------------------------------------------------------add test user----------------------


fastify.listen({port : 9223, host: '0.0.0.0'}, (err)=>{
  if (err){
    fastify.log.error("info [user]: Error:",err);
    process.exit(1);
  }
  console.log("info [user]: listening to port 9223");
});

