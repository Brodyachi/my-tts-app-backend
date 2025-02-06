import {express,nodemailer,bodyParser,cors,bcrypt,pg,path,WebSocketServer,textToSpeech,fs,fileURLToPath,util,multer,cloudinary,session,axios
} from './dependencies.js';

import dotenv from 'dotenv';

const { v2: cloudinaryV2 } = cloudinary;

dotenv.config({ path: './secret.env' });

const PORT = 5001;
const app = express();
const codes = new Map(); 
app.use(bodyParser.json());
app.use(cors());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const apiToken = process.env.YANDEX_API_KEY;
const folderToken = process.env.FOLDER_ID;
async function synthesizeText(text) {
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
          Authorization: "Api-Key " + apiToken
      },
      data: params,
      responseType: 'stream', 
  })
    response.data.pipe(fs.createWriteStream('./newFile2.ogg'))
    console.log('Аудиофайл сохранен');
  } catch (error) {
    console.error('Ошибка при синтезе речи:', error.response?.data || error.message);
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
  htmlTemplate = htmlTemplate.replace('{{email}}', email).replace('{{code}}', code);
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

    if (userCheckResult.rows.length > 0) {
      const isMatch = await bcrypt.compare(password, userCheckResult.rows[0].password);
      if (isMatch) {
        req.session.user = userCheckResult.rows[0].id;
        return res.status(200).json({ message: 'Успешный вход' });
      } else {
        return res.status(401).json({ message: 'Неправильный логин или пароль. Попробуйте еще раз.' });
      }
    }
  } catch (error) {
    console.error('Ошибка входа пользователя:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
});

app.post('/api-request', async (req, res) => {
  const { text } = req.body;
  console.log(text);
  try {
    synthesizeText(text);
    return res.status(200).json({ message: 'Обработано' });
  } catch (error) {
    console.error('Ошибка запроса:', error);
    res.status(500).json({ message: 'Внутренняя ошибка сервера', success: false });
  }
})

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
