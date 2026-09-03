const COOKIE_NAME = "__Host-mariage_session";
const SESSION_TTL = 60 * 60 * 24 * 30; // 30 jours

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Déconnexion
    if (url.pathname === "/__auth/logout") {
      return new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie": `${COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`,
        },
      });
    }

    // Connexion
    if (url.pathname === "/__auth/login" && request.method === "POST") {
      const form = await request.formData();
      const password = String(form.get("password") || "");

      if (password !== env.SITE_PASSWORD) {
        return loginPage("Mot de passe incorrect.", 401);
      }

      const session = await createSession(env.SESSION_SECRET);

      return new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie":
            `${COOKIE_NAME}=${session}; Max-Age=${SESSION_TTL}; ` +
            `Path=/; Secure; HttpOnly; SameSite=Lax`,
        },
      });
    }

    // Vérification de la session avant TOUT accès au site
    const authenticated = await verifySession(
      request,
      env.SESSION_SECRET
    );

    if (!authenticated) {
      return loginPage();
    }

    // Session valide : on laisse Cloudflare servir index.html
    return env.ASSETS.fetch(request);
  },
};

async function createSession(secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const nonce = crypto.randomUUID();

  const payload = `${expires}.${nonce}`;
  const signature = await sign(payload, secret);

  return `${base64url(payload)}.${signature}`;
}

async function verifySession(request, secret) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const match = cookieHeader.match(
    new RegExp(`${COOKIE_NAME}=([^;]+)`)
  );

  if (!match) return false;

  try {
    const [encodedPayload, signature] = match[1].split(".");

    if (!encodedPayload || !signature) return false;

    const payload = base64urlDecode(encodedPayload);
    const [expires] = payload.split(".");

    if (!expires || Number(expires) < Math.floor(Date.now() / 1000)) {
      return false;
    }

    const expectedSignature = await sign(payload, secret);

    return signature === expectedSignature;
  } catch {
    return false;
  }
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return base64url(new Uint8Array(signature));
}

function base64url(value) {
  const bytes =
    typeof value === "string"
      ? new TextEncoder().encode(value)
      : value;

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(value) {
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "===".slice((value.length + 3) % 4);

  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

  return new TextDecoder().decode(bytes);
}

function loginPage(error = "", status = 200) {
  return new Response(
    `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Accès privé</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #f7f3ee;
      font-family: system-ui, sans-serif;
      color: #333;
    }
    .box {
      width: min(90%, 420px);
      padding: 40px;
      background: white;
      border-radius: 20px;
      box-shadow: 0 10px 40px rgba(0,0,0,.08);
      text-align: center;
    }
    h1 { margin-top: 0; }
    p { color: #666; }
    input {
      width: 100%;
      padding: 14px;
      margin: 20px 0 12px;
      border: 1px solid #ddd;
      border-radius: 10px;
      font-size: 16px;
    }
    button {
      width: 100%;
      padding: 14px;
      border: 0;
      border-radius: 10px;
      background: #333;
      color: white;
      font-size: 16px;
      cursor: pointer;
    }
    .error {
      color: #b42318;
      margin-bottom: 15px;
    }
  </style>
</head>
<body>
  <main class="box">
    <h1>Site privé</h1>
    <p>Entrez le mot de passe pour accéder au site.</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <form method="POST" action="/__auth/login">
      <input
        type="password"
        name="password"
        placeholder="Mot de passe"
        autocomplete="current-password"
        required
        autofocus
      >
      <button type="submit">Entrer</button>
    </form>
  </main>
</body>
</html>`,
    {
      status,
      headers: {
        "Content-Type": "text/html; charset=UTF-8",
        "Cache-Control": "no-store",
      },
    }
  );
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[char]));
}
