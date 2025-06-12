
# Aplicación Web Base

Aplicación web base con un inicio de sesión, conexión a PostgreSQL y uso de JWT.




## Instalación

Descargamos el proyecto utilizando git clone:

```bash
  git clone https://github.com/UqMr1/basic-login-register.git
  cd basic-login-register
```
    
Una vez descargado, instalamos las dependencias necesarias:

```bash
  npm init -y
  npm install express pg dotenv bcrypt jsonwebtoken cors cookie-parser
```


## Despliegue de base de datos en PostgreSQL.
Creamos una base de datos en PostgreSQL y ejecutamos esta script para crear la siguiente la tabla:

*Esta parte no es obligatoria, ya que cuando inicamos la apliación comprueba si existe la tabla y si no existe la crea automáticamente.*

```sql
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

```
## Configuración

Creación del archivo .env:


```bash
  DB_USER=postgres
  DB_PASSWORD=mysecretpassword
  DB_HOST=localhost
  DB_PORT=5432
  DB_DATABASE=your_db_name
  JWT_SECRET=your_secret_password
```
En este archivo configuramos la conexión a la base de datos. También, tenemos una variable en la que escribiremos el secret de JWT.

Para iniciar el servidor, escribimos:

```bash
  node server.js
```

Ahora accedemos a http://localhost:3000
## Funcionamiento del código
```bash
JWT-OAuth2.0-main/
├── private/
│   └── dashboard.html
├── public/
│   ├── login.html
│   ├── register.html
│   └── styles.css
├── .env
├── bd.js
└── server.js


```
A continuación, explicaré cual es la función de los archivos, sus funciones, su código... de forma detallada:


**.env**

En el archivo .env definimos las variables de entorno necesarias para que la aplicación funcione.
Definimos las variables para conectar la aplicación a la base de datos y el [secret de JWT](https://javascript.com.es/como-usar-jwt-en-javascript).

Guardamos variables sensibles en archivos .env por seguridad. Cuando están guardadas en una variable de entorno, es muy dificíl acceder a ellas mediante el código ya que están guardadas a nivel de sistema.

**bd.js**

Este archivo es el encargado de realizar las conexiones a la base de datos utilizando los valores de la variables de entorno.

Tiene mas funciones como la de crear la tabla users si no existe.

```javascript
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
```

**server.js**

Función register:

Sirve register.html del direcotrio public en /register.

```javascript
  app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
}); 
```
Define una ruta que responde a solicitudes POST en la URL '/register'.

```javascript
  app.post('/register', async (req, res) => {...})
```
Captura los datos con las etiqueta email y password enviadas a través de la petición POST desde el formulario:

```javascript
  try {
    const { email, password } = req.body;
```
Comprueba que los campos no estén vaciós ni sean valores nulos:

```javascript
if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
```
Esta parte del código verifica si el correo electrónico es existente en la base de datos. Hace una petición preguntandole a la base de datos si existe un email igual que el que se ha escrito en el formulario.

La comprobación la realiza analizando la longitud de la respuesta de la base de datos. Si esta longitud es mayor a 0, devuelve que el usuario ya existe.

```javascript
  const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
```

Creamos la variable salt. El salt, es una cadena de texto aleatoria que se le aplica a una contraseña antes de cifrarla. El parámetro 10 (cost factor) son las veces que se aplicará el algoritmo de cifrado para generar el salt.

Una vez tengamos la función/variable de salt, creamos la de hashedPassword. 

hashedPassword unirá la contraseña escrita en el formulario de registro con el salt generado por la función anterior y aplica un algoritmo de cifrado basado en BlowFish repetidas según el cost factor.

```javascript
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
```
La última parte del registro de usuarios, consiste en realizar una inserción del correo electrónico y la contraseña hasheada en la base de datos:

```javascript
  const result = await db.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
```

Función Login:
![Resumen](https://i.imgur.com/DKmZNYk.png)
![Resumen Login](https://i.imgur.com/JpDoMvA.png)


Al igual que register, sirve el formulario login.html del directorio public en /login:

```javascript
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
```

Definimos una ruta post (/login) con la que manejamos solicitudes de inicio de sesión.

Estas solicitudes las enviamos desde el formulario /login.
Las capturamos con la siguiente linea de código:

```javascript
try {
    const { email, password } = req.body;
```

Comprueba que los campos no estén vaciós ni sean valores nulos:

```javascript
if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
```

Ahora, hacemos una consulta y lo guardamos en la variable (result). Con esta consulta lo que hacemos es la tabla users si existe un email igual que el que hemos escrito en el formulario de login.

Definimos también la variable user que recoge la id, el email y la contraseña (hasheada) del resultado de la petición anterior.

```javascript
const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
const user = result.rows[0];
```

Comprueba si la variable user no existe o está vacía. Si está vacía devuleve un error 400 con el mensaje "Credenciales inválidas".

```javascript
if (!user) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }
```
Con la función "bcrypt.comparte" comparamos al contraseña escrita por el usuario en el formulario con la contraseña hasehada en la base de datos. Si coinciden, devolverá el valor true, con lo cual el valor de validPassword será true.
Si no coinciden, no devolverá ningún valor, entonces nos devolverá un error 400 con el mensaje "Credenciales inválidas".

```javascript
const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }
```

Con jwt.sign generamos el token JWT con los siguientes parámetros en el payload:

- email: user.email (Extraemos el email del usuario)
- También se le añade una fecha de creación y otra de expiración.

Seguidamente, se añade clave secreta para firmar el token. Esta clave se encuentra almacenada en la variable de entorno "JWT_SECRET" que hemos definido en el archivo .env.

Y por último, añadimos la opción de expiración del token. Esta, está configurada a 1 hora, pero siempre podemos modficarlo según nos convenga.

Con todo esto, ya tenemos nuestro token configurado correctamente.

```javascript
const token = jwt.sign(
    { email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
);
```

Esta es una función de Express que establece una cookie en la respuesta HTTP. Configura el nombre de la cookie (token), el valor de la cookie (token generado con la función anterior) y una lista de opciones:

- httpOnly: false (permite que la cookie sea accesible por el Javascript del navegador)
- maxAge:  3600000 (duración de la cookie, después de ese tiempo, la cookie se expirará y el navegador la eliminará)
- path: '/' (la cookie está disponible en todas las ruta de la aplicación web)

```javascript
res.cookie('token', token, { 
    httpOnly: false, 
    maxAge: 3600000, // 1 hora
    path: '/' 
});
```

Una vez programado el token de acceso, vamos a crear el token de refresco.
El token de refreso o *refresh token* se utiliza para renovar el token de acceso.
Con esto conseguimos sesiónes mas duraderas y mas seguras, ya que crearemos un sistema para poder "banear" refresh tokens y cerrar sesiones en caso de que los tokens sean robados.



```javascript
const refreshToken = jwt.sign(
      { email: user.email },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' } // 7 días
    );
    
```

Cuando se genere el token, se guardará en una tabla de la base de datos, junto a la id del usuario al que le pertenece:

```sql
await db.query(
      'INSERT INTO refresh_token (token, user_id) VALUES ($1, $2)',
      [refreshToken, user.id]
    );
```

- Cuando el access token tenga que renovarse, se comprobará que el cliente tiene un refresh token válido. Al mismo tiempo, este refresh token tiene que existir en la base de datos. Si el refresh token no es válido o no existe en la base de datos, la sesión se cerrará automáticamente.

El refreh token también se almacenará en una cookie segura:

```javascript
res.cookie('refreshToken', refreshToken, { 
      httpOnly: true, // No accesible por JavaScript
      secure: false,
      sameSite: 'Strict',
      maxAge: 604800000, // 7 días
      path: '/' // Solo disponible para rutas /auth
    });
```




Una vez completado todo el proceso de inicio de sesión correctamente, redirige a la URL /dashboard.

```javascript
res.redirect('/dashboard');
```

Hacemos que dashobard.html aparezca en /dashboard:

```javascript
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
```

**Fucnión para cerrar sesión (logout)**

```javascript
app.get('/logout',async (req, res) => {
  res.clearCookie('token');
  res.clearCookie('refreshToken');
  res.redirect('/login');
  await db.query(
    'DELETE FROM refresh_token WHERE token = $1',
    [req.cookies.refreshToken]
  );
});

```

Esta función eliminará las cookies que almacenan el refresh y el access token, redireccionará a la página de inicio de sesión, y eliminará ese refresh token de la base de datos.


**Middleware "RequireAuth"**
![Resumen middleware](https://i.imgur.com/dLMGiwX.png)

Este middleware comprobará que el usuario tenga cookies de la página almacenadas en el navegador, si no las tiene, redirige al inicio de sesión.

```javascript
async function requireAuth (req, res, next) {
  if (!req.cookies) {
    return res.status(401).redirect('/login');
  }
```
En el siguiente bloque de código, almacena en la variable token, el valor de las cookies "token".
Y en la variable refreshToken, el valor de las cookies "refreshToken".
Si la variable token está vacía, vuelve a dirigir a login.


```javascript
const token = req.cookies.token;
const refreshToken = req.cookies.refreshToken;
  
if (!token) {
  return res.status(401).redirect('/login');
}
```

Una vez estén las cookies almacenadas en variables, empezamos con un try - catch.
Este try - catch intentará verificar si el access token es correcto. Si lo consigue, concederá el acceso. Si no lo consigue, hará lo siguiente:


```javascript
try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.email = decoded;
    console.log("Access Token válido");
    next();
  }
```

Si el access token está caducado, no es válido... Se comprobará si existe un refresh token almacenado en las cookies. Si no existe, se redirigirá a /login.
Si está almacenado en las cookies, comprobará en la base de datos si existe. Si no existe en la base de datos, se redirigirá a login, si existe, empezará otro try - catch para renovar el access token.


```javascript
catch (err) {
  console.log("Access Token no válido");
  if (err.name == 'TokenExpiredError') {
    console.log("Access Token Expirado");
    console.log("Reasginando token");
  if (!refreshToken) {
    return res.status(401).redirect('/login');
  }
  const refreshTokenResult = await db.query( 'SELECT * FROM refresh_token WHERE token = $1', [refreshToken]);
  if (refreshTokenResult.rows.length === 0) {
    return res.status(401).redirect('/login');
  }
```

Si el refresh token existe en la base de datos, procede a comprobar que sea válido. Si el refresh token es válido, se vuelve a crear un access token que reemplazará al anterior, ya que ha expirado, permitiendo acceder a los recursos protegidos.
Este nuevo access token se guarda en la misma cookie "token" y ya podriamos acceder a los recursos protegidos con un nuevo access token.


```javascript
try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const newToken = jwt.sign(
          { email: decoded.email },
          process.env.JWT_SECRET,
          { expiresIn: '1m' }
        );
        console.log("Guardando cookie...")
        res.cookie('token', newToken, {
          httpOnly: true,
          secure: false,
          sameSite: 'Lax',
          maxAge:   60 * 60 * 1000,
          path: '/' 
        });
        return next();
```
Si fallara la parte anterior, saltaría un error 403 y no se renovaría el token.

```javascript
}catch (error) {
  console.error('Error al refrescar token:', error);
  res.status(403).json({ error: 'Token inválido o expirado' });  
}
```
**Con esto, ya tendríamos nuestro middleware con verificación de access y refresh token funcionando.**


Con este código, servimos páginas privadas. Definimos que toda petición GET a ese endpoint, pase por nuestra función requireAuth.

```javascript
 app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, './private', 'dashboard.html'));
  });
```
