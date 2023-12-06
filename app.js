const mysql = require('mysql');
const express = require('express');
const path = require('path');
const crypto = require('crypto');
var jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const { escape } = require('html-escaper');
const nodemailer = require('nodemailer');
require('dotenv').config()

const app = express();
const PORT = process.env.SV_PORT;
const secretKey = process.env.JWT_KEY;

const tokensInvalidos = [];

const dbConfig = {
  host: process.env.DB_IP,
  user: process.env.DB_USR,
  password: process.env.DB_PW,
  database: process.env.DB_DB,
};

let transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secureConnection: false,
  tls: {rejectUnauthorized: false},
  debug:true
});

let emailSent = false;
 
const connection = mysql.createConnection(dbConfig);
  
app.use(express.json());

// ################### CLIENT ####################

app.use(express.static(path.join(__dirname, 'client')));

app.get('/login', async (req, res) => {
  
    res.sendFile(path.join(__dirname, 'client', 'login.html'));

});

app.get('/logout', removeCookie, (req, res) => {
  
  res.redirect('/login');
});

app.get('/public', (req, res) => {

  const searchTerm = escape(req.query.termo || '');

  fs.readFile(path.join(__dirname, 'client', 'public.html'), 'utf8', (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Erro interno no servidor.');
    }

    const replacedHTML = data.replace(/{{#SEARCH_TERM#}}/g, searchTerm);

    res.send(replacedHTML);
  });
});

app.get('/aluno', verificarTokenCookie, (req, res) => {
  
    res.sendFile(path.join(__dirname, 'client', 'aluno.html'));

});

app.get('/professor', verificarTokenCookie, (req, res) => {
  
    res.sendFile(path.join(__dirname, 'client', 'professor.html'));

});

// ################# SERVER ###################

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT 
                    U.name AS name, 
                    U.password AS password,
                    U.username AS username,
                    U.salt AS salt,
                    P.telaId AS telaId,
                    T.name AS telaName,
                    T.path AS telaPath
                      FROM security_app.users U, security_app.permissoes P, security_app.telas T
                        WHERE U.userId = P.userId
                          AND P.telaId = T.telaId
                          AND U.username = ?;`;

    connection.query(query, [username], (err, results) => {
      if (err) {
        console.error('Erro ao executar a consulta:', err);
        return;
      }  
      

      if(results.length == 0){
        res.status(200).json({
            FLAG: 'E',
            RETURN: 'Usuário não existe'
        })
        insertFailedLogin(req, username || '', password || '');
      } else if(results[0].password == hashStringWithSHA256(password, results[0].salt)){
        const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
        res.status(200).cookie('token', token, { httpOnly: true }).json({
            token,
            FLAG: 'S',
            RETURN: {
              name: results[0].name,
              username: results[0].username,
              tela: results[0].telaPath
            }
        })
      } else {
        res.status(200).json({
            FLAG: 'E',
            RETURN: 'Senha incorreta'
        })
        insertFailedLogin(req, username || '', password || '');
      }
      
    });
  });

app.post('/api/getPublic', (req, res) => {

  const searchTerm = req.body.termo || '';

  let query = 'SELECT * FROM security_app.cursos ';
  const params = [];
  
  if (searchTerm) {
    query += 'WHERE UPPER(name) LIKE ?';
    params.push(`%${searchTerm.toUpperCase()}%`);
  }
  
  connection.query(query, params, (err, results, fields) => {
      if (err) {
        res.status(200).json({
          FLAG: 'E',
          RETURN: 'Erro ao executar a consulta:' + err
      })
        return;
      }        

      if(results.length == 0){
        res.status(200).json({
            FLAG: 'E',
            RETURN: 'Nenhum resultado'
        })
      } else {
        res.status(200).json({
            FLAG: 'S',
            RETURN: results.map(row => ({
              cursoId: row.cursoId,
              name: decryptValue(row.name),
              professor: decryptValue(row.professor)
            }))
        })
      }
      
    });
  });

  app.use((req, res) => {
    res.redirect('/login');
  });

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });

// #################### FUNCTIONS ###################

const encryptionKey = process.env.ENCRYPT_KEY;

function encryptValue(value) {
  const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
  let encryptedValue = cipher.update(value, 'utf8', 'hex');
  encryptedValue += cipher.final('hex');
  return encryptedValue;
}

function decryptValue(encryptedValue) {
  const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
  let decryptedValue = decipher.update(encryptedValue, 'hex', 'utf8');
  decryptedValue += decipher.final('utf8');
  return decryptedValue;
}

function insertFailedLogin(req, username, password) {
  const failedLoginQuery = `INSERT INTO failed_login_log (dateTime, reqIp, reqUsername, reqPw) VALUES (NOW(), ?, ?, ?)`;
  connection.query(failedLoginQuery, [(req.ip == "::1") ? "127.0.0.1" : req.ip, username, password], (err) => {
    if (err) {
      console.error('Erro ao inserir os dados da requisição de login falhado:', err);
      return;
    }
  });
}

function verificarTokenCookie(req, res, next) {
  
  cookieParser()(req, res, () => {
    const token = req.cookies.token;

    if (tokensInvalidos.includes(token)) {
      return res.redirect('/login');
    }

    if (!token) {
      return res.redirect('/login');
    }

    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.redirect('/login');
      }
      req.user = decoded.user;
      next();
    });
  });
}

function removeCookie(req, res, next) {
  
  cookieParser()(req, res, () => {
    const token = req.cookies.token;

    tokensInvalidos.push(token);

    next();
  });
}

function hashStringWithSHA256(input, salt) {
  const hash = crypto.createHash('sha256');
  hash.update(input + salt);
  return hash.digest('hex');
}

function checkFailedLogins() {
  const query = `SELECT COUNT(*) as total FROM failed_login_log WHERE dateTime >= NOW() - INTERVAL 10 MINUTE;`;

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Erro ao executar a consulta:', err);
      return;
    }

    const total = results[0].total;

    if (total > 50 && !emailSent) {
      const mailOptions = {
        from: 'Security Monitoring <noreply@hyundai-brasil.com>',
        to: ['joao.medinilha@aluno.ifsp.edu.br', 'medinilha.jplm1818@gmail.com'],
        subject: 'Alerta de Ataque de Força Bruta',
        html: `
          <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
            <h1 style="color: #FF9800; text-align: center;">Alerta de Ataque de Força Bruta</h1>
            <p>Caro(a) destinatário(a),</p>
            <p style="background-color: #FFEB3B; padding: 10px; border-radius: 4px;">Há um ataque de força bruta em andamento! Foram registradas ${total} tentativas de login nos últimos 10 minutos.</p>
            <p>Por favor, tome as medidas necessárias para proteger sua conta e reforçar a segurança.</p>
            <p>Atenciosamente,</p>
            <p>Sua Equipe de Monitoramento</p>
          </div>
        `
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) {
          console.error('Erro ao enviar o e-mail:', error);
        } else {
          console.log('E-mail enviado com sucesso!');
          emailSent = true;
          setTimeout(() => { emailSent = false; }, 10 * 60 * 1000);
        }
      });
    } 
  });
}

function runLoop() {
  checkFailedLogins();

  setTimeout(runLoop, 1000);
}

runLoop();

// ############### gera key aleatoria

// const generateSecretKey = () => {
//   return crypto.randomBytes(32).toString('hex');
// };

// console.log(generateSecretKey());

// ############# criptografa minha tabela 

// connection.query('SELECT * FROM cursos', (err, results) => {
//   if (err) {
//     console.error('Erro ao executar a consulta:', err);
//     return;
//   }

//   for (let i = 0; i < results.length; i++) {
//     const row = results[i];

//     const encryptedName = encryptValue(row.name);
//     const encryptedProfessor = encryptValue(row.professor);

//     connection.query('UPDATE cursos SET name = ?, professor = ? WHERE cursoId = ?', 
//       [encryptedName, encryptedProfessor, row.cursoId], (error, result) => {
//         if (error) {
//           console.error('Erro ao atualizar os valores criptografados:', error);
//         }
//       });
//   }
// });


// ######## gerar salt 

// const crypto = require('crypto');

// const generateSalt = () => {
//   console.log(crypto.randomBytes(16).toString('hex'));
// };

// generateSalt();

// ########## gerar hash com salt

// const bcrypt = require('bcryptjs');

// const password = '';
// const salt = ''


// const generateHashWithSalt = (password, salt) => {
//   return bcrypt.hashSync(password + salt, 10);
// };

// console.log(generateHashWithSalt(password, salt));