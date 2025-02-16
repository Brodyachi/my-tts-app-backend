import {express,nodemailer,bodyParser,cors,bcrypt,pg,path,WebSocketServer,fs,fileURLToPath,util,multer,session,axios
} from './dependencies.js';

import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import pgSession from 'connect-pg-simple';
import cron from 'node-cron';
import mammoth from 'mammoth';
import * as pdfjsLib from 'pdfjs-dist';

dotenv.config({ path: './secret.env' });

const PORT = 5001;
const app = express();
const codes = new Map(); 
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  store: new (pgSession(session))({
    conObject: {
      user: 'myuser',
      host: '127.10.11.5',
      database: 'server',
      password: 'mypassword',
      port: 5432,
    }
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
  }
}));

app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true,
}));

app.get('/read-cookie', (req, res) => {
  console.log(req.cookies);
  console.log(req.cookies.sessionId);
  res.send(req.cookies);
});

const __filename1 = fileURLToPath(import.meta.url);
const __dirname1 = path.dirname(__filename1);
app.use('/public', express.static(path.join(__dirname1, 'public')));

app.use((req, res, next) => {
  if (req.session.user) {
    const now = Date.now();
    if (now - (req.session.lastActivity || now) > 30 * 60 * 1000) {
      console.log(`Сессия завершена из-за бездействия: ${req.session.user}`);
      req.session.destroy(err => {
        if (err) console.error('Ошибка при удалении сессии:', err);
      });
      return res.status(401).json({ message: 'Сессия истекла, войдите снова' });
    }
    req.session.lastActivity = now;
  }
  next();
});

app.use((req, res, next) => {
  if (req.session.user) {
    console.log(`Активность пользователя ${req.session.user} на ${new Date().toISOString()}`);
  }
  next();
});

cron.schedule('0 0 * * *', async () => {
  try {
    await client.query(`DELETE FROM messages WHERE created_at < NOW() - INTERVAL '1 day'`);
    console.log('Старые сообщения удалены');
  } catch (error) {
    console.error('Ошибка при очистке сообщений:', error);
  }
});

const apiToken = process.env.YANDEX_API_KEY;
const folderToken = process.env.FOLDER_ID;

async function synthesizeText(session_user, text) {
  const params = new URLSearchParams();
  params.append('text', text);
  params.append('voice', 'ermil');
  params.append('emotion', 'neutral');
  params.append('lang', 'ru-RU');
  params.append('speed', '0.7');
  params.append('format', 'oggopus');

  try {
    const response = await axios({
      method: 'POST',
      url: 'https://tts.api.cloud.yandex.net/speech/v1/tts:synthesize',
      headers: {
        Authorization: "Api-Key " + apiToken,
      },
      data: params,
      responseType: 'stream',
    });

    const filename = `${Date.now()}_${session_user}.ogg`;
    const request_string = path.join(__dirname, 'public/requests', filename);
    const writeStream = fs.createWriteStream(request_string);

    response.data.pipe(writeStream);

    await new Promise((resolve, reject) => {
      writeStream.on('finish', resolve);
      writeStream.on('error', reject);
    });

    const insertQuery = 'INSERT INTO requests (fk_user_id, audio_pos) VALUES ($1, $2)';
    await client.query(insertQuery, [session_user, `http://localhost:5001/public/requests/${filename}`]);

    console.log('Аудиофайл сохранен:', request_string);
    return request_string;
  } catch (error) {
    console.error('Ошибка при синтезе речи:', error.response?.data || error.message);
    throw new Error('Ошибка при синтезе речи');
  }
}

const { Client } = pg;
const client = new Client({
    user: 'myuser',
    host: '127.10.11.5',
    database: 'server',
    password: 'mypassword',
    port: 5432,  
})

await client.connect();

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  auth: {
      user: 'rasamailapllication@gmail.com',
      pass: process.env.EMAIL_PASSWORD,
  }
});

app.listen(PORT, () => {
  console.log('Сервер работает');
});

app.get('/', (req, res) => {
    res.send('Hello');
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const templatePath = path.join(__dirname, 'emailTemplate.html');

app.post('/send-code', (req, res) => {
  const email = req.body.email;


  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }

  const code = Math.floor(100000 + Math.random() * 900000);
  codes.set(email, { code, expires: Date.now() + 10 * 60 * 1000 });
  let htmlTemplate = fs.readFileSync(templatePath, 'utf-8');
  htmlTemplate = htmlTemplate.replace('${email}', email).replace('${code}', code);
  const mailOptions = {
    from: '"Joe Peach 🍑"<rasamailapllication@gmail.com>',
    to: email,
    subject: 'RASA Registration Process',
    text: `Ваш код подтверждения: ${code}`,
    html: htmlTemplate,
  };
  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      return res.status(500).json({ message: 'Ошибка отправки кода' });
    }
    res.status(200).json({ message: 'Код отправлен успешно' });
  });
});

app.post('/verify-code', async (req, res) => {
  const { email, code, username, password } = req.body;

  if (!email || !code || !username || !password) {
    return res.status(400).json({ message: 'Все поля обязательны' });
  }

  const storedData = codes.get(email);
  if (!storedData || storedData.code !== parseInt(code) || storedData.expires < Date.now()) {
    return res.status(400).json({ message: 'Неверный или просроченный код' });
  }

  codes.delete(email);

  try {
    const userCheckQuery = 'SELECT * FROM users WHERE login = $1';
    const userCheckResult = await client.query(userCheckQuery, [username]);
    const emailCheckQuery = 'SELECT * FROM users WHERE email = $1';
    const emailCheckResult = await client.query(emailCheckQuery, [email]);
    if (emailCheckResult.rows.length > 0) {
      return res.status(400).json({ message: 'Email уже зарегистрирован' });
    }
    if (userCheckResult.rows.length > 0) {
      return res.status(400).json({ message: 'Пользователь уже существует' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const insertQuery = 'INSERT INTO users (login, password, email) VALUES ($1, $2, $3)';
    await client.query(insertQuery, [username, hashedPassword, email]);

    res.status(201).json({ message: 'Пользователь зарегистрирован успешно', success: true });
  } catch (error) {
    console.error('Ошибка регистрации пользователя:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});

app.post('/log-in', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Все поля обязательны' });
  }

  try {
    const userCheckQuery = 'SELECT id, password FROM users WHERE login = $1';
    const userCheckResult = await client.query(userCheckQuery, [username]);

    if (userCheckResult.rows.length === 0) {
      return res.status(401).json({ message: 'Неправильные учетные данные' });
    }

    const isMatch = await bcrypt.compare(password, userCheckResult.rows[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Неправильные учетные данные' });
    }

    req.session.user = userCheckResult.rows[0].id;
    console.log('Сессия сохранена:', req.session);

    return res.status(200).json({ message: 'Успешный вход' });
  } catch (error) {
    console.error('Ошибка входа пользователя:', error);
    return res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});


app.post('/api-request', async (req, res) => {
  const { text } = req.body;
  const session_user = req.session.user;

  if (!session_user) {
    return res.status(401).json({ message: "Сессия не найдена" });
  }

  try {
    await client.query(
      `INSERT INTO messages (user_id, text, sender) VALUES ($1, $2, 'user')`,
      [session_user, text]
    );

    await synthesizeText(session_user, text);
    const userCheckQuery = `
      SELECT audio_pos FROM requests 
      WHERE fk_user_id = $1 
      ORDER BY id DESC LIMIT 1
    `;
    const userCheckResult = await client.query(userCheckQuery, [session_user]);

    if (userCheckResult.rows.length > 0) {
      const audioUrl = userCheckResult.rows[0].audio_pos;
      await client.query(
        `INSERT INTO messages (user_id, text, sender) VALUES ($1, $2, 'bot')`,
        [session_user, audioUrl]
      );

      return res.status(200).json({ request_url: audioUrl });
    } else {
      return res.status(404).json({ message: "Аудиофайл не найден" });
    }
  } catch (error) {
    console.error('Ошибка запроса:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});




app.post('/log-out', (req, res) => {
  if (req.session.user) {
    console.log(`Сессия завершена для пользователя с ID: ${req.session.user}`);
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: 'Ошибка при завершении сессии' });
      }
      res.status(200).json({ message: 'Выход выполнен успешно' });
    });
  } else {
    res.status(400).json({ message: 'Пользователь не авторизован' });
  }
});

app.get('/session-info', (req, res) => {
  if (req.session.user) {
      const remainingTime = req.session.cookie.expires
          ? new Date(req.session.cookie.expires) - Date.now()
          : req.session.cookie.maxAge;

      console.log(`Сессия пользователя: ${JSON.stringify(req.session.user, null, 2)}`);
      console.log(`Оставшееся время сессии: ${Math.round(remainingTime / 1000)} сек`);

      return res.json({ 
          user: req.session.user, 
          remainingTime: Math.round(remainingTime / 1000) 
      });
  }
  res.status(401).json({ message: 'Нет активной сессии' });
});


app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Пользователь не авторизован' });
  }
  res.status(200).json({ message: 'Профиль', userId: req.session.user });
});

app.get('/chat-history', async (req, res) => {
  const session_user = req.session.user;
  if (!session_user) {
    return res.status(401).json({ message: "Сессия не найдена" });
  }

  try {
    const messagesQuery = `
      SELECT text, sender, created_at FROM messages
      WHERE user_id = $1 
      ORDER BY created_at ASC
    `;
    const messages = await client.query(messagesQuery, [session_user]);

    return res.status(200).json(messages.rows);
  } catch (error) {
    console.error('Ошибка получения истории чата:', error);
    return res.status(500).json({ message: "Ошибка сервера" });
  }
});

async function readFileContent(filePath, fileType) {
  try {
    if (fileType === 'text/plain') {
      return fs.readFileSync(filePath, 'utf-8');
    } else if (fileType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
      const result = await mammoth.extractRawText({ path: filePath });
      return result.value;
    } else if (fileType === 'application/pdf') {
      const dataBuffer = fs.readFileSync(filePath);
      const loadingTask = pdfjsLib.getDocument(dataBuffer);
      const pdf = await loadingTask.promise;
      let textContent = '';

      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const text = await page.getTextContent();
        text.items.forEach((item) => {
          textContent += item.str + ' ';
        });
      }

      return textContent;
    } else {
      throw new Error('Неподдерживаемый формат файла');
    }
  } catch (error) {
    console.error('Ошибка чтения файла:', error);
    throw error;
  }
}

const upload = multer({ dest: 'uploads/' });

app.post('/upload-document', upload.single('document'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Файл не загружен' });
  }
  const session_user = req.session.user;
  if (!session_user) {
    return res.status(401).json({ message: "Сессия не найдена" });
  }
  try {
    const filePath = req.file.path;
    const fileType = req.file.mimetype;
    const fileName = req.file.originalname;
    await client.query(
      `INSERT INTO messages (user_id, text, sender) 
       VALUES ($1, $2, 'user')`,
      [session_user, `Файл: ${fileName}`]
    );
    const fileContent = await readFileContent(filePath, fileType);
    fs.unlinkSync(filePath);

    await synthesizeText(session_user, fileContent);
    const userCheckQuery = `
      SELECT audio_pos FROM requests 
      WHERE fk_user_id = $1 
      ORDER BY id DESC LIMIT 1
    `;
    const userCheckResult = await client.query(userCheckQuery, [session_user]);

    if (userCheckResult.rows.length > 0) {
      const audioUrl = userCheckResult.rows[0].audio_pos;
      await client.query(
        `INSERT INTO messages (user_id, text, sender) 
         VALUES ($1, $2, 'bot')`,
        [session_user, audioUrl]
      );

      return res.status(200).json({ request_url: audioUrl });
    } else {
      return res.status(404).json({ message: "Аудиофайл не найден" });
    }
  } catch (error) {
    console.error('Ошибка обработки документа:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});