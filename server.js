import { express, nodemailer, bodyParser, cors, bcrypt, pg, path, WebSocketServer, fs, fileURLToPath, util, multer, session, axios } from './dependencies.js';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import pgSession from 'connect-pg-simple';
import cron from 'node-cron';
import mammoth from 'mammoth';
import logger from 'winston';
import * as pdfjsLib from 'pdfjs-dist';
import DOMPurify from 'dompurify';
import JSDOM from 'jsdom';
import hpp from 'hpp';

dotenv.config({ path: './secret.env' });

function pass_gen(len) {
  const chrs = 'abdehkmnpswxzABDEFGHKMNPQRSTWXZ123456789!@#$%^&*()';
  let str = '';
  for (let i = 0; i < len; i++) {
    const pos = Math.floor(Math.random() * chrs.length);
    str += chrs.substring(pos, pos + 1);
  }
  return str;
}

const PORT = 5001;
const app = express();
const window = new JSDOM.JSDOM('').window;
const purify = DOMPurify(window);
const codes = new Map();

app.use(hpp());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  store: new (pgSession(session))({
    conString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

const corsOptions = {
  origin: [
    'https://my-tts-app-frontend-vite.onrender.com',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

app.options('*', cors(corsOptions));

const __filename1 = fileURLToPath(import.meta.url);
const __dirname1 = path.dirname(__filename1);
app.use('/public', express.static(path.join(__dirname1, 'public')));

app.use((req, res, next) => {
  if (req.session.user) {
    const now = Date.now();
    if (now - (req.session.lastActivity || now) > 30 * 60 * 1000) {
      logger.info(`Сессия завершена из-за бездействия: ${req.session.user}`);
      req.session.destroy(err => {
        if (err) logger.error('Ошибка при удалении сессии:', err);
      });
      return res.status(401).json({ message: 'Сессия истекла, войдите снова' });
    }
    req.session.lastActivity = now;
  }
  next();
});

app.use((req, res, next) => {
  if (req.session.user) {
    logger.info(`Активность пользователя ${req.session.user} на ${new Date().toISOString()}`);
  }
  next();
});

cron.schedule('0 0 * * *', async () => {
  try {
    await pool.query(`DELETE FROM messages WHERE created_at < NOW() - INTERVAL '1 day'`);
    logger.info('Старые сообщения удалены');
  } catch (error) {
    logger.error('Ошибка при очистке сообщений:', error);
  }
});



const apiToken = process.env.YANDEX_API_KEY;
const folderToken = process.env.FOLDER_ID;

async function synthesizeText(session_user, text, voice, emotion, speed, format) {
  const params = new URLSearchParams();
  params.append('text', text);
  params.append('voice', voice);
  params.append('emotion', emotion);
  params.append('lang', 'ru-RU');
  params.append('speed', speed);
  params.append('format', format);

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
      writeStream.on('error', (err) => {
        logger.error('Ошибка записи файла:', err);
        fs.unlinkSync(request_string);
        reject(err);
      });
    });

    const insertQuery = 'INSERT INTO requests (fk_user_id, audio_pos) VALUES ($1, $2)';
    await pool.query(insertQuery, [session_user, `https://rasa-tts-server.onrender.com/public/requests/${filename}`]);

    logger.info('Аудиофайл сохранен:', request_string);
    return request_string;
  } catch (error) {
    logger.error('Ошибка при синтезе речи:', error.response?.data || error.message);
    throw new Error('Ошибка при синтезе речи');
  }
}

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  auth: {
    user: 'rasamailapllication@gmail.com',
    pass: process.env.EMAIL_PASSWORD,
  }
});

app.listen(PORT, () => {
  logger.info(`Сервер работает на порту ${PORT}`);
});

app.get('/', (req, res) => {
  res.send('Hello');
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const templateEPath = path.join(__dirname, 'emailTemplate.html');
const templatePPath = path.join(__dirname, 'passwordTemplate.html');

app.post('/send-code', (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }

  const code = Math.floor(100000 + Math.random() * 900000);
  codes.set(email, { code, expires: Date.now() + 10 * 60 * 1000 });
  let htmlTemplate = fs.readFileSync(templateEPath, 'utf-8');
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
      logger.error('Ошибка отправки кода:', error);
      return res.status(500).json({ message: 'Ошибка отправки кода' });
    }
    res.status(200).json({ message: 'Код отправлен успешно' });
  });
});

app.post('/password-reset', async (req, res) => {
  const email = req.body.email;
  if (!email) {
    return res.status(400).json({ message: 'Email обязателен' });
  }
  try {
    const emailCheckQuery = 'SELECT * FROM users WHERE email = $1';
    const emailCheckResult = await pool.query(emailCheckQuery, [email]);
    if (emailCheckResult.rows.length === 0) {
      return res.status(404).json({ message: 'Пользователь с такой почтой не найден' });
    }
    const code = pass_gen(12);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(code, salt);
    const updatePasswordQuery = 'UPDATE users SET password = $1 WHERE email = $2';
    await pool.query(updatePasswordQuery, [hashedPassword, email]);
    let htmlTemplate = fs.readFileSync(templatePPath, 'utf-8');
    htmlTemplate = htmlTemplate.replace('${email}', email).replace('${code}', code);
    const mailOptions = {
      from: '"Joe Peach 🍑"<rasamailapllication@gmail.com>',
      to: email,
      subject: 'RASA Registration Process',
      text: `Ваш пароль сброшен, новый пароль: ${code}`,
      html: htmlTemplate,
    };
    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        logger.error('Ошибка сброса пароля:', error);
        return res.status(500).json({ message: 'Ошибка сброса пароля' });
      }
      res.status(200).json({ message: 'Пароль сброшен успешно' });
    });
  } catch (error) {
    logger.error('Ошибка сброса пароля:', error);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
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
    const userCheckResult = await pool.query(userCheckQuery, [username]);
    const emailCheckQuery = 'SELECT * FROM users WHERE email = $1';
    const emailCheckResult = await pool.query(emailCheckQuery, [email]);
    if (emailCheckResult.rows.length > 0) {
      return res.status(400).json({ message: 'Email уже зарегистрирован' });
    }
    if (userCheckResult.rows.length > 0) {
      return res.status(400).json({ message: 'Пользователь уже существует' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const insertQuery = 'INSERT INTO users (login, password, email) VALUES ($1, $2, $3)';
    await pool.query(insertQuery, [username, hashedPassword, email]);

    res.status(201).json({ message: 'Пользователь зарегистрирован успешно', success: true });
  } catch (error) {
    logger.error('Ошибка регистрации пользователя:', error);
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
    const userCheckResult = await pool.query(userCheckQuery, [username]);

    if (userCheckResult.rows.length === 0) {
      return res.status(401).json({ message: 'Неправильные учетные данные' });
    }

    const isMatch = await bcrypt.compare(password, userCheckResult.rows[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Неправильные учетные данные' });
    }

    req.session.user = userCheckResult.rows[0].id;
    logger.info('Сессия сохранена:', req.session);

    return res.status(200).json({ message: 'Успешный вход' });
  } catch (error) {
    logger.error('Ошибка входа пользователя:', error);
    return res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});

app.post('/api-request', async (req, res) => {
  const { text, ttsSettings } = req.body;
  const voice = ttsSettings.voice;
  const emotion = ttsSettings.emotion;
  const speed = ttsSettings.speed;
  const format = ttsSettings.format;
  const session_user = req.session.user;

  if (!session_user) {
    return res.status(401).json({ message: "Сессия не найдена" });
  }

  try {
    await pool.query(
      `INSERT INTO messages (user_id, text, sender) VALUES ($1, $2, 'user')`,
      [session_user, text]
    );

    await synthesizeText(session_user, text, voice, emotion, speed, format);
    const userCheckQuery = `
      SELECT audio_pos FROM requests 
      WHERE fk_user_id = $1 
      ORDER BY id DESC LIMIT 1
    `;
    const userCheckResult = await pool.query(userCheckQuery, [session_user]);

    if (userCheckResult.rows.length > 0) {
      const audioUrl = userCheckResult.rows[0].audio_pos;
      await pool.query(
        `INSERT INTO messages (user_id, text, sender) VALUES ($1, $2, 'bot')`,
        [session_user, audioUrl]
      );

      return res.status(200).json({ request_url: audioUrl });
    } else {
      return res.status(404).json({ message: "Аудиофайл не найден" });
    }
  } catch (error) {
    logger.error('Ошибка запроса:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});

app.post('/log-out', (req, res) => {
  if (req.session.user) {
    logger.info(`Сессия закрыта для пользователя: ${req.session.user}`);

    res.clearCookie('connect.sid', {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    req.session.destroy((err) => {
      if (err) {
        logger.error('Ошибка закрытия сессии:', err);
        return res.status(500).json({ message: 'Logout failed' });
      }
      return res.status(200).json({ 
        message: 'Успешный выход',
        logout: true 
      });
    });
  } else {
    res.status(401).json({ message: 'Пользователь не авторизован' });
  }
});

app.get('/session-info', (req, res) => {
  if (req.session.user) {
    const remainingTime = req.session.cookie.expires
      ? new Date(req.session.cookie.expires) - Date.now()
      : req.session.cookie.maxAge;

    logger.info(`Сессия пользователя: ${JSON.stringify(req.session.user, null, 2)}`);
    logger.info(`Оставшееся время сессии: ${Math.round(remainingTime / 1000)} сек`);

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
    const messages = await pool.query(messagesQuery, [session_user]);

    return res.status(200).json(messages.rows);
  } catch (error) {
    logger.error('Ошибка получения истории чата:', error);
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
    logger.error('Ошибка чтения файла:', error);
    throw error;
  }
}

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['text/plain', 'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Неподдерживаемый формат файла'), false);
    }
  }
});

app.post('/upload-document', upload.single('document'), async (req, res) => {
  const file = req.file;
  const ttsSettings = JSON.parse(req.body.ttsSettings);
  const voice = ttsSettings.voice;
  const emotion = ttsSettings.emotion;
  const speed = ttsSettings.speed;
  const format = ttsSettings.format;
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
    await pool.query(
      `INSERT INTO messages (user_id, text, sender) 
       VALUES ($1, $2, 'user')`,
      [session_user, `Файл: ${fileName}`]
    );
    const fileContent = await readFileContent(filePath, fileType);
    fs.unlinkSync(filePath);
    await synthesizeText(session_user, fileContent, voice, emotion, speed, format);
    const userCheckQuery = `
      SELECT audio_pos FROM requests 
      WHERE fk_user_id = $1 
      ORDER BY id DESC LIMIT 1
    `;
    const userCheckResult = await pool.query(userCheckQuery, [session_user]);

    if (userCheckResult.rows.length > 0) {
      const audioUrl = userCheckResult.rows[0].audio_pos;
      await pool.query(
        `INSERT INTO messages (user_id, text, sender) 
         VALUES ($1, $2, 'bot')`,
        [session_user, audioUrl]
      );

      return res.status(200).json({ request_url: audioUrl });
    } else {
      return res.status(404).json({ message: "Аудиофайл не найден" });
    }
  } catch (error) {
    logger.error('Ошибка обработки документа:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});

app.post('/changepassword', async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const session_user = req.session.user;

  if (!session_user) {
    return res.status(401).json({ message: 'Пользователь не авторизован' });
  }

  try {
    const userCheckQuery = 'SELECT password FROM users WHERE id = $1';
    const userCheckResult = await pool.query(userCheckQuery, [session_user]);

    if (userCheckResult.rows.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
    const isMatch = await bcrypt.compare(oldPassword, userCheckResult.rows[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Неверный старый пароль' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const updatePasswordQuery = 'UPDATE users SET password = $1 WHERE id = $2';
    await pool.query(updatePasswordQuery, [hashedPassword, session_user]);
      return res.status(200).json({ 
        message: 'Пароль успешно изменен. Вы вышли из всех устройств.',
        logout: true 
      });
  } catch (error) {
    logger.error('Ошибка смены пароля:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});

app.get('/user/:id', async (req, res) => {
  if (!req.session.user || req.session.user != req.params.id) {
    return res.status(403).json({ message: 'Доступ запрещен' });
  }

  try {
    const userQuery = 'SELECT id, login, email FROM users WHERE id = $1';
    const userResult = await pool.query(userQuery, [req.params.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    res.status(200).json(userResult.rows[0]);
  } catch (error) {
    logger.error('Ошибка получения данных пользователя:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера' });
  }
});
