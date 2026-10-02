const COOKIE_NAME = "site_auth";
const COOKIE_MAX_AGE = 24 * 60 * 60; // 24 heures

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - value.length % 4) % 4);

  const binary = atob(padded);

  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  return crypto.subtle.digest("SHA-256", data);
}

async function hmac(secret, message) {
  const keyData = new TextEncoder().encode(secret);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  return crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function passwordIsCorrect(password, expectedPassword) {
  const a = new Uint8Array(await sha256(password));
  const b = new Uint8Array(await sha256(expectedPassword));

  return constantTimeEqual(a, b);
}

async function createSession(password) {
  const expires = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;

  const signature = new Uint8Array(
    await hmac(password, String(expires))
  );

  return `${expires}.${base64url(signature)}`;
}

async function validSession(cookie, password) {
  if (!cookie || !password) return false;

  const parts = cookie.split(".");

  if (parts.length !== 2) return false;

  const expires = Number(parts[0]);
  const signature = parts[1];

  if (!Number.isFinite(expires)) return false;

  if (expires < Math.floor(Date.now() / 1000)) {
    return false;
  }

  const expected = new Uint8Array(
    await hmac(password, String(expires))
  );

  let received;

  try {
    received = base64urlToBytes(signature);
  } catch {
    return false;
  }

  return constantTimeEqual(received, expected);
}

function getCookie(request, name) {
  const header = request.headers.get("cookie");

  if (!header) return null;

  const cookies = header.split(";");

  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

function passwordPage(error = "") {
  return `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Accès protégé</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: Arial, sans-serif;
      background: #f2f2f2;
    }

    .login {
      width: 90%;
      max-width: 400px;
      padding: 35px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 5px 25px rgba(0,0,0,0.15);
      text-align: center;
    }

    h1 {
      margin-top: 0;
      margin-bottom: 25px;
      font-size: 26px;
    }

    input {
      width: 100%;
      padding: 12px;
      margin-bottom: 15px;
      border: 1px solid #ccc;
      border-radius: 6px;
      font-size: 16px;
    }

    button {
      width: 100%;
      padding: 12px;
      border: 0;
      border-radius: 6px;
      background: #333;
      color: white;
      font-size: 16px;
      cursor: pointer;
    }

    button:hover {
      background: #555;
    }

    .error {
      color: #c00;
      margin-bottom: 15px;
    }
  </style>
</head>

<body>

  <div class="login">

    <h1>Site privé</h1>

    ${error ? `<div class="error">${error}</div>` : ""}

    <form method="POST">

      <input
        type="password"
        name="password"
        placeholder="Mot de passe"
        autocomplete="current-password"
        required
        autofocus
      >

      <button type="submit">
        Entrer
      </button>

    </form>

  </div>

</body>
</html>
`;
}

export default async (request, context) => {

  const password = Netlify.env.get("PROTECTED_PAGE_PASSWORD");

  // Sécurité : si le mot de passe n'est pas configuré,
  // le site reste inaccessible.
  if (!password) {
    return new Response(
      "Le site n'est pas encore configuré. Le propriétaire doit définir PROTECTED_PAGE_PASSWORD dans Netlify.",
      {
        status: 503,
        headers: {
          "content-type": "text/plain; charset=UTF-8"
        }
      }
    );
  }

  const url = new URL(request.url);

  // Déconnexion
  if (url.pathname === "/__logout") {

    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/",
        "Set-Cookie":
          `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`
      }
    });
  }

  // Vérification de la session
  const cookie = getCookie(request, COOKIE_NAME);

  if (await validSession(cookie, password)) {

    // Visiteur déjà authentifié :
    // Netlify sert normalement le fichier demandé.
    return context.next();
  }

  // Traitement du formulaire de connexion
  if (request.method === "POST") {

    let form;

    try {
      form = await request.formData();
    } catch {
      return new Response(
        passwordPage("Requête invalide."),
        {
          status: 400,
          headers: {
            "content-type": "text/html; charset=UTF-8"
          }
        }
      );
    }

    const enteredPassword = form.get("password");

    if (
      typeof enteredPassword === "string" &&
      await passwordIsCorrect(enteredPassword, password)
    ) {

      const session = await createSession(password);

      return new Response(null, {
        status: 302,

        headers: {
          "Location": "/",

          "Set-Cookie":
            `${COOKIE_NAME}=${session}; Max-Age=${COOKIE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Strict`
        }
      });
    }

    return new Response(
      passwordPage("Mot de passe incorrect."),
      {
        status: 401,
        headers: {
          "content-type": "text/html; charset=UTF-8"
        }
      }
    );
  }

  // Pas encore connecté :
  // afficher la page de connexion.
  return new Response(
    passwordPage(),
    {
      status: 401,
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store"
      }
    }
  );
};

export const config = {
  path: "/*"
};