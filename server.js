const express = require("express");
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { RtcRole, RtcTokenBuilder } = require("agora-token");
const { AccessToken } = require("livekit-server-sdk");
const nodemailer = require("nodemailer");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

const drivers = new Map(); // key: socketId
const admins = new Set(); // socketIds
const trips = new Map(); // key: tripId
const ACCESS_STORE_PATH = path.join(__dirname, "driver_access_store.json");
const ACCOUNT_STORE_PATH = path.join(__dirname, "account_profile_store.json");
const driverAccessProfiles = new Map(); // key: id
const accountProfiles = new Map(); // key: accountKey
const AUTH_HASH_PREFIX = "hmac-sha256:";
const AUTH_HASH_PEPPER = "atob::dispatch::secure::2026";
const FIXED_ADMIN_EMAIL = normalizeEmail(
  process.env.ATOB_ADMIN_EMAIL || "devb12004@gmail.com",
);
const FIXED_ADMIN_CREDENTIAL_ID = "admin:primary";
const FIXED_ADMIN_PASSWORD_HASH = asString(
  process.env.ATOB_ADMIN_PASSWORD_HASH,
  "hmac-sha256:6cd3ac218bd61b2d0e2068e68778ca8ded4b0b140fa67edde51d1109f19c4de5",
);

let channelBusy = false;
let channelOwnerId = null;
let channelLockedAt = 0;
const CHANNEL_BUSY_TTL_MS = 8000;
const AGORA_APP_ID = asString(
  process.env.AGORA_APP_ID,
  "f33bdf0e58e242fd808fe52b6157a22d",
);
const AGORA_APP_CERTIFICATE = asString(process.env.AGORA_APP_CERTIFICATE);
const AGORA_TOKEN_TTL_SECONDS = Math.max(
  120,
  asNumber(process.env.AGORA_TOKEN_TTL_SECONDS, 3600),
);
const LIVEKIT_URL = asString(process.env.LIVEKIT_URL);
const LIVEKIT_API_KEY = asString(process.env.LIVEKIT_API_KEY);
const LIVEKIT_API_SECRET = asString(process.env.LIVEKIT_API_SECRET);
const LIVEKIT_ROOM_NAME = asString(
  process.env.LIVEKIT_ROOM_NAME,
  "atob-intercom",
);
const LIVEKIT_TOKEN_TTL = asString(process.env.LIVEKIT_TOKEN_TTL, "12h");
const SMTP_HOST = asString(process.env.SMTP_HOST);
const SMTP_PORT = Math.trunc(asNumber(process.env.SMTP_PORT, 587));
const SMTP_SECURE = asString(process.env.SMTP_SECURE).toLowerCase() === "true";
const SMTP_USER = asString(process.env.SMTP_USER);
const SMTP_PASS = asString(process.env.SMTP_PASS);
const SMTP_FROM_EMAIL = asString(
  process.env.SMTP_FROM_EMAIL,
  SMTP_USER || "dispatch@atobmobility.com",
);
const SMTP_FROM_NAME = asString(
  process.env.SMTP_FROM_NAME,
  "AtoB Dispatch",
);
const RESEND_API_KEY = asString(process.env.RESEND_API_KEY);
const RESEND_FROM_EMAIL = asString(
  process.env.RESEND_FROM_EMAIL,
  "onboarding@resend.dev",
);
const RESEND_FROM_NAME = asString(
  process.env.RESEND_FROM_NAME,
  SMTP_FROM_NAME || "AtoB Dispatch",
);
const PUBLIC_BASE_URL = asString(
  process.env.PUBLIC_BASE_URL,
  "https://atob-server-1.onrender.com",
);
let inviteTransporter = null;

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

function nowIso() {
  return new Date().toISOString();
}

function asString(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  let text = String(value).trim();
  text = text.replace(/^\uFEFF/, "");
  if (
    (text.startsWith('"') && text.endsWith('"')) ||
    (text.startsWith("'") && text.endsWith("'"))
  ) {
    text = text.slice(1, -1).trim();
  }
  return text || fallback;
}

function asNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function normalizeLocation(
  raw,
  fallback = { latitude: 0, longitude: 0 },
) {
  if (!raw || typeof raw !== "object") return fallback;
  const latitude = asNumber(raw.latitude, fallback.latitude);
  const longitude = asNumber(raw.longitude, fallback.longitude);
  return {
    latitude,
    longitude,
    speed: asNumber(raw.speed, 0),
    timestamp: raw.timestamp ? String(raw.timestamp) : null,
  };
}

function normalizeEmail(value) {
  return asString(value).toLowerCase();
}

function isSecureHash(value) {
  const text = asString(value);
  return text.startsWith(AUTH_HASH_PREFIX) && text.length > AUTH_HASH_PREFIX.length;
}

function hashSecret({ scope, identity, secret }) {
  const normalizedScope = asString(scope).toLowerCase();
  const normalizedIdentity = asString(identity).toLowerCase();
  const normalizedSecret = asString(secret);
  if (!normalizedScope || !normalizedIdentity || !normalizedSecret) {
    return "";
  }
  const key = `${AUTH_HASH_PEPPER}|${normalizedScope}`;
  const payload = `${normalizedScope}|${normalizedIdentity}|${normalizedSecret}`;
  const digest = crypto
    .createHmac("sha256", key)
    .update(payload)
    .digest("hex");
  return `${AUTH_HASH_PREFIX}${digest}`;
}

function ensureSecretHash({ scope, identity, secretOrHash }) {
  const value = asString(secretOrHash);
  if (!value) return "";
  if (isSecureHash(value)) return value;
  return hashSecret({ scope, identity, secret: value });
}

function secretTail(secret) {
  const value = asString(secret);
  if (!value) return "";
  return value.length <= 2 ? value : value.slice(-2);
}

function activationTokenHash(profileId, token) {
  return hashSecret({
    scope: "driver-activation",
    identity: profileId,
    secret: token,
  });
}

function hasInviteEmailConfig() {
  return hasResendConfig() || hasSmtpConfig();
}

function hasSmtpConfig() {
  return Boolean(
    SMTP_HOST &&
      SMTP_PORT > 0 &&
      SMTP_FROM_EMAIL &&
      SMTP_USER &&
      SMTP_PASS,
  );
}

function hasResendConfig() {
  return Boolean(RESEND_API_KEY && RESEND_FROM_EMAIL);
}

function getInviteTransporter() {
  if (!hasSmtpConfig()) return null;
  inviteTransporter ??= nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
  return inviteTransporter;
}

function buildActivationUrl(token) {
  const base = PUBLIC_BASE_URL.replace(/\/+$/, "");
  return `${base}/access/activate?token=${encodeURIComponent(token)}`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderActivationShell({ title, body, accent = "#00B5FF", autoClose = false }) {
  const closeScript = autoClose
    ? `
      <script>
        setTimeout(() => {
          window.close();
          setTimeout(() => {
            if (document.body) {
              const note = document.getElementById("close-note");
              if (note) note.style.display = "block";
            }
          }, 400);
        }, 3200);
      </script>
    `
        : "";
  return `<!doctype html>
  <html lang="es">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${title}</title>
      <style>
        :root {
          color-scheme: dark;
          --bg: #040506;
          --panel: rgba(10, 12, 16, 0.9);
          --panel-soft: rgba(255,255,255,0.045);
          --panel-strong: rgba(255,255,255,0.065);
          --text: #f5f7fa;
          --muted: #a7b1bf;
          --accent: ${accent};
          --accent-soft: rgba(0,181,255,0.16);
          --accent-line: rgba(0,181,255,0.32);
          --line: rgba(255,255,255,0.08);
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          min-height: 100vh;
          display: grid;
          place-items: center;
          background:
            radial-gradient(circle at top left, rgba(0,181,255,0.22), transparent 34%),
            radial-gradient(circle at top right, rgba(92,117,255,0.14), transparent 28%),
            radial-gradient(circle at bottom, rgba(255,255,255,0.04), transparent 36%),
            linear-gradient(180deg, #08090b 0%, var(--bg) 100%);
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: var(--text);
          padding: 20px;
        }
        .card {
          position: relative;
          overflow: hidden;
          width: min(100%, 520px);
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 32px;
          padding: 28px;
          box-shadow: 0 36px 100px rgba(0,0,0,0.46);
          backdrop-filter: blur(22px);
        }
        .card::before {
          content: "";
          position: absolute;
          inset: -1px;
          pointer-events: none;
          background:
            linear-gradient(135deg, rgba(255,255,255,0.12), transparent 30%),
            radial-gradient(circle at top right, var(--accent-soft), transparent 38%);
          mask:
            linear-gradient(#000 0 0) content-box,
            linear-gradient(#000 0 0);
          -webkit-mask:
            linear-gradient(#000 0 0) content-box,
            linear-gradient(#000 0 0);
          mask-composite: exclude;
          -webkit-mask-composite: xor;
          padding: 1px;
        }
        .topbar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 14px;
          margin-bottom: 18px;
        }
        .mark {
          width: 68px;
          height: 68px;
          border-radius: 20px;
          display: grid;
          place-items: center;
          font-weight: 900;
          letter-spacing: -0.06em;
          background:
            linear-gradient(135deg, rgba(255,255,255,0.22), rgba(255,255,255,0.04)),
            linear-gradient(135deg, var(--accent), #64d6ff);
          color: #041018;
          box-shadow: 0 20px 48px rgba(0,181,255,0.28);
        }
        .eyebrow {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 8px 12px;
          border-radius: 999px;
          background: var(--panel-soft);
          border: 1px solid var(--line);
          font-size: 12px;
          font-weight: 700;
          color: #d8e4ef;
          letter-spacing: 0.02em;
        }
        .eyebrow::before {
          content: "";
          width: 8px;
          height: 8px;
          border-radius: 999px;
          background: var(--accent);
          box-shadow: 0 0 0 6px rgba(0,181,255,0.12);
        }
        .hero {
          position: relative;
          margin-bottom: 18px;
          padding: 20px 20px 18px;
          border-radius: 24px;
          background:
            linear-gradient(135deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
            radial-gradient(circle at top right, rgba(0,181,255,0.16), transparent 42%);
          border: 1px solid rgba(255,255,255,0.08);
        }
        .hero::after {
          content: "";
          position: absolute;
          top: 18px;
          right: 18px;
          width: 82px;
          height: 82px;
          border-radius: 24px;
          background:
            linear-gradient(135deg, rgba(255,255,255,0.12), rgba(255,255,255,0.02)),
            linear-gradient(135deg, rgba(0,181,255,0.18), rgba(100,214,255,0.04));
          border: 1px solid rgba(255,255,255,0.08);
          box-shadow: inset 0 0 0 1px rgba(255,255,255,0.03);
        }
        .hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 12px;
          padding: 8px 12px;
          border-radius: 999px;
          background: rgba(255,255,255,0.05);
          border: 1px solid rgba(255,255,255,0.08);
          color: #dce7f2;
          font-size: 12px;
          font-weight: 800;
        }
        .hero-badge::before {
          content: "";
          width: 10px;
          height: 10px;
          border-radius: 999px;
          background: var(--accent);
          box-shadow: 0 0 0 7px rgba(0,181,255,0.11);
        }
        h1 {
          margin: 0 0 10px;
          max-width: 320px;
          font-size: 34px;
          line-height: 1.03;
          letter-spacing: -0.03em;
        }
        p {
          margin: 0 0 12px;
          color: var(--muted);
          line-height: 1.6;
          font-size: 15px;
        }
        .hero-copy {
          max-width: 330px;
          margin: 0;
        }
        .stack {
          display: grid;
          gap: 14px;
        }
        .button, button {
          appearance: none;
          border: 0;
          background: linear-gradient(135deg, var(--accent), #64d6ff);
          color: #041018;
          font-weight: 800;
          border-radius: 999px;
          padding: 15px 18px;
          cursor: pointer;
          width: 100%;
          margin-top: 6px;
          font-size: 15px;
          box-shadow: 0 16px 34px rgba(0,181,255,0.22);
          transition: transform 0.18s ease, box-shadow 0.18s ease;
        }
        .button:hover, button:hover {
          transform: translateY(-1px);
          box-shadow: 0 18px 36px rgba(0,181,255,0.26);
        }
        .info {
          margin: 0;
          padding: 14px 16px;
          border-radius: 20px;
          background: rgba(255,255,255,0.035);
          border: 1px solid var(--line);
        }
        .label {
          display: block;
          margin-bottom: 6px;
          font-size: 12px;
          font-weight: 700;
          letter-spacing: 0.04em;
          text-transform: uppercase;
          color: #8f9baa;
        }
        .metrics {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
        }
        .metric {
          padding: 14px 16px;
          border-radius: 20px;
          background: rgba(255,255,255,0.035);
          border: 1px solid var(--line);
        }
        .metric strong {
          display: block;
          margin-top: 4px;
          color: #fff;
          font-size: 15px;
          line-height: 1.4;
          word-break: break-word;
        }
        .checklist {
          margin: 0;
          padding: 0;
          list-style: none;
          display: grid;
          gap: 10px;
        }
        .checklist li {
          display: flex;
          align-items: flex-start;
          gap: 10px;
          color: var(--muted);
          line-height: 1.5;
          font-size: 14px;
        }
        .checklist li::before {
          content: "";
          flex: 0 0 auto;
          width: 10px;
          height: 10px;
          margin-top: 6px;
          border-radius: 999px;
          background: var(--accent);
          box-shadow: 0 0 0 6px rgba(0,181,255,0.1);
        }
        .accent-line {
          height: 1px;
          margin: 6px 0 2px;
          background: linear-gradient(90deg, var(--accent-line), transparent);
        }
        .meta {
          margin-top: 16px;
          font-size: 12px;
          color: #8f96a1;
          line-height: 1.5;
        }
        @media (max-width: 560px) {
          body { padding: 14px; }
          .card { padding: 20px; border-radius: 26px; }
          .hero { padding: 18px 16px 16px; }
          .hero::after { width: 64px; height: 64px; border-radius: 18px; }
          h1 { max-width: 100%; font-size: 29px; }
          .hero-copy { max-width: 100%; }
          .metrics { grid-template-columns: 1fr; }
        }
      </style>
    </head>
    <body>
      <main class="card">
        <div class="topbar">
          <div class="mark">A2</div>
          <div class="eyebrow">AtoB Activation</div>
        </div>
        <section class="hero">
          <div class="hero-badge">Private driver invitation</div>
          <h1>${title}</h1>
          <p class="hero-copy">Acceso privado, activacion segura y preparacion lista para operar dentro de AtoB.</p>
        </section>
        <section class="stack">
          ${body}
        </section>
        <p class="meta" id="close-note" style="display:none">Si esta ventana no se cierra sola, ya puedes volver a la app.</p>
      </main>
      ${closeScript}
    </body>
  </html>`;
}

function postJson(url, { headers = {}, body = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const request = https.request(
      url,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          ...headers,
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = raw ? JSON.parse(raw) : null;
          } catch (_) {
            json = null;
          }
          resolve({
            statusCode: response.statusCode || 0,
            raw,
            json,
          });
        });
      },
    );
    request.on("error", reject);
    request.write(payload);
    request.end();
  });
}

async function sendInviteEmailWithResend({ profile, activationUrl, safeName, safeEmail, safeUrl }) {
  const response = await postJson("https://api.resend.com/emails", {
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
    },
    body: {
      from: `"${RESEND_FROM_NAME}" <${RESEND_FROM_EMAIL}>`,
      to: [profile.email],
      subject: "Tu acceso a AtoB esta listo",
      text:
        `Hola ${profile.displayName}.\n\n` +
        `Tu cuenta de AtoB ya fue creada por operaciones.\n` +
        `Correo asignado: ${profile.email}\n` +
        `Activa tu cuenta aqui: ${activationUrl}\n\n` +
        `Si no esperabas este mensaje, puedes ignorarlo.`,
      html: `
        <div style="margin:0;padding:32px 18px;background:#060708;color:#f4f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          <div style="max-width:620px;margin:0 auto;background:linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02));border:1px solid rgba(255,255,255,0.08);border-radius:32px;padding:30px;box-shadow:0 32px 80px rgba(0,0,0,0.42);">
            <div style="display:inline-grid;place-items:center;width:64px;height:64px;border-radius:20px;background:linear-gradient(135deg,#00B5FF,#6AD8FF);color:#041018;font-weight:900;font-size:26px;box-shadow:0 18px 44px rgba(0,181,255,0.30);">A2</div>
            <div style="margin-top:16px;display:inline-block;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);font-size:12px;font-weight:700;color:#d5e4ef;">AtoB Dispatch Invitation</div>
            <h1 style="margin:18px 0 10px;font-size:32px;line-height:1.02;letter-spacing:-0.03em;">Tu acceso esta listo</h1>
            <p style="margin:0 0 12px;color:#b4bcc7;line-height:1.65;font-size:15px;">
              Hola ${safeName}, operaciones preparo tu cuenta de AtoB para que empieces a trabajar con acceso privado y seguro.
            </p>
            <div style="margin:18px 0 10px;padding:16px;border-radius:18px;background:rgba(255,255,255,0.035);border:1px solid rgba(255,255,255,0.08);">
              <div style="font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#8f9baa;margin-bottom:6px;">Correo asignado</div>
              <div style="font-size:15px;font-weight:700;color:#ffffff;">${safeEmail}</div>
            </div>
            <p style="margin:0 0 14px;color:#b4bcc7;line-height:1.65;font-size:15px;">
              Usa la clave temporal entregada por tu administrador y activa tu cuenta para desbloquear el inicio de sesion.
            </p>
            <a href="${safeUrl}" style="display:inline-block;margin-top:6px;background:linear-gradient(135deg,#00B5FF,#6AD8FF);color:#041018;text-decoration:none;font-weight:800;padding:15px 20px;border-radius:999px;box-shadow:0 16px 34px rgba(0,181,255,0.22);">
              Activar cuenta
            </a>
            <p style="margin:20px 0 10px;color:#8f96a1;font-size:12px;line-height:1.6;">
              Si el boton no abre, copia este enlace en tu navegador:
            </p>
            <p style="margin:0;padding:14px 16px;border-radius:16px;background:#0d1014;border:1px solid rgba(255,255,255,0.06);font-size:12px;line-height:1.55;word-break:break-all;color:#d3dbe6;">
              ${safeUrl}
            </p>
            <p style="margin:18px 0 0;color:#8f96a1;font-size:12px;line-height:1.6;">
              Si no esperabas este mensaje, puedes ignorarlo. Esta invitacion fue emitida por AtoB Dispatch.
            </p>
          </div>
        </div>
      `,
    },
  });

  if (response.statusCode < 200 || response.statusCode >= 300) {
    const resendMessage =
      response.json?.message ||
      response.json?.error?.message ||
      response.raw ||
      "Error desconocido de Resend";
    throw new Error(`Resend: ${resendMessage}`);
  }

  return {
    sent: true,
    provider: "resend",
    messageId: response.json?.id || null,
  };
}

async function sendInviteEmail({ profile, activationUrl }) {
  const safeName = escapeHtml(profile.displayName || "Driver");
  const safeEmail = escapeHtml(profile.email || "");
  const safeUrl = escapeHtml(activationUrl);
  if (hasResendConfig()) {
    return sendInviteEmailWithResend({
      profile,
      activationUrl,
      safeName,
      safeEmail,
      safeUrl,
    });
  }
  const transporter = getInviteTransporter();
  if (!transporter) {
    throw new Error(
      "No hay proveedor de correo configurado en Render. Agrega SMTP_* o RESEND_API_KEY + RESEND_FROM_EMAIL.",
    );
  }
  await transporter.sendMail({
    from: `"${SMTP_FROM_NAME}" <${SMTP_FROM_EMAIL}>`,
    to: profile.email,
    subject: "Tu acceso a AtoB esta listo",
    text:
      `Hola ${profile.displayName}.\n\n` +
      `Tu cuenta de AtoB ya fue creada por operaciones.\n` +
      `Correo asignado: ${profile.email}\n` +
      `Activa tu cuenta aqui: ${activationUrl}\n\n` +
      `Si no esperabas este mensaje, puedes ignorarlo.`,
    html: `
      <div style="margin:0;padding:32px 18px;background:#060708;color:#f4f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
        <div style="max-width:620px;margin:0 auto;background:linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02));border:1px solid rgba(255,255,255,0.08);border-radius:32px;padding:30px;box-shadow:0 32px 80px rgba(0,0,0,0.42);">
          <div style="display:inline-grid;place-items:center;width:64px;height:64px;border-radius:20px;background:linear-gradient(135deg,#00B5FF,#6AD8FF);color:#041018;font-weight:900;font-size:26px;box-shadow:0 18px 44px rgba(0,181,255,0.30);">A2</div>
          <div style="margin-top:16px;display:inline-block;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);font-size:12px;font-weight:700;color:#d5e4ef;">AtoB Dispatch Invitation</div>
          <h1 style="margin:18px 0 10px;font-size:32px;line-height:1.02;letter-spacing:-0.03em;">Tu acceso esta listo</h1>
          <p style="margin:0 0 12px;color:#b4bcc7;line-height:1.65;font-size:15px;">
            Hola ${safeName}, operaciones preparó tu cuenta de AtoB para que empieces a trabajar con acceso privado y seguro.
          </p>
          <div style="margin:18px 0 10px;padding:16px;border-radius:18px;background:rgba(255,255,255,0.035);border:1px solid rgba(255,255,255,0.08);">
            <div style="font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#8f9baa;margin-bottom:6px;">Correo asignado</div>
            <div style="font-size:15px;font-weight:700;color:#ffffff;">${safeEmail}</div>
          </div>
          <p style="margin:0 0 14px;color:#b4bcc7;line-height:1.65;font-size:15px;">
            Usa la clave temporal entregada por tu administrador y activa tu cuenta para desbloquear el inicio de sesión.
          </p>
          <a href="${safeUrl}" style="display:inline-block;margin-top:6px;background:linear-gradient(135deg,#00B5FF,#6AD8FF);color:#041018;text-decoration:none;font-weight:800;padding:15px 20px;border-radius:999px;box-shadow:0 16px 34px rgba(0,181,255,0.22);">
            Activar cuenta
          </a>
          <p style="margin:20px 0 10px;color:#8f96a1;font-size:12px;line-height:1.6;">
            Si el botón no abre, copia este enlace en tu navegador:
          </p>
          <p style="margin:0;padding:14px 16px;border-radius:16px;background:#0d1014;border:1px solid rgba(255,255,255,0.06);font-size:12px;line-height:1.55;word-break:break-all;color:#d3dbe6;">
            ${safeUrl}
          </p>
          <p style="margin:18px 0 0;color:#8f96a1;font-size:12px;line-height:1.6;">
            Si no esperabas este mensaje, puedes ignorarlo. Esta invitación fue emitida por AtoB Dispatch.
          </p>
        </div>
      </div>
    `,
  });
  return {
    sent: true,
    provider: "smtp",
  };
}

async function sendWelcomeEmailWithResend({ profile, safeName, safeEmail }) {
  const response = await postJson("https://api.resend.com/emails", {
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
    },
    body: {
      from: `"${RESEND_FROM_NAME}" <${RESEND_FROM_EMAIL}>`,
      to: [profile.email],
      subject: "Bienvenido a AtoB: tu cuenta ya esta activa",
      text:
        `Hola ${profile.displayName}.\n\n` +
        `Tu cuenta de AtoB ya quedo activada correctamente.\n` +
        `Correo asignado: ${profile.email}\n\n` +
        `Nos alegra tenerte dentro. Ya puedes abrir la app, iniciar sesion y empezar tu ruta con una operacion clara, segura y profesional.\n\n` +
        `Bienvenido a bordo.\nAtoB Dispatch`,
      html: `
        <div style="margin:0;padding:32px 18px;background:#050607;color:#f4f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          <div style="max-width:640px;margin:0 auto;background:radial-gradient(circle at top left, rgba(61,220,151,0.20), transparent 38%),linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02));border:1px solid rgba(255,255,255,0.08);border-radius:34px;padding:32px;box-shadow:0 34px 90px rgba(0,0,0,0.42);">
            <div style="display:inline-grid;place-items:center;width:68px;height:68px;border-radius:22px;background:linear-gradient(135deg,#3DDC97,#72BBFF);color:#071018;font-weight:900;font-size:28px;box-shadow:0 20px 46px rgba(61,220,151,0.26);">A2</div>
            <div style="margin-top:16px;display:inline-block;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);font-size:12px;font-weight:800;color:#d8e5ef;">Welcome to AtoB</div>
            <h1 style="margin:18px 0 10px;font-size:34px;line-height:1.02;letter-spacing:-0.03em;">Tu cuenta ya esta activa</h1>
            <p style="margin:0 0 12px;color:#b4bcc7;line-height:1.7;font-size:15px;">
              Hola ${safeName}, tu acceso ya quedo confirmado y listo para usarse. Este es el inicio de una experiencia mas fluida, clara y profesional dentro de AtoB.
            </p>
            <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:20px 0;">
              <div style="padding:16px;border-radius:18px;background:rgba(255,255,255,0.035);border:1px solid rgba(255,255,255,0.08);">
                <div style="font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#8f9baa;margin-bottom:6px;">Estado</div>
                <div style="font-size:16px;font-weight:800;color:#ffffff;">Cuenta activa</div>
              </div>
              <div style="padding:16px;border-radius:18px;background:rgba(255,255,255,0.035);border:1px solid rgba(255,255,255,0.08);">
                <div style="font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#8f9baa;margin-bottom:6px;">Correo asignado</div>
                <div style="font-size:15px;font-weight:700;color:#ffffff;">${safeEmail}</div>
              </div>
            </div>
            <div style="padding:18px;border-radius:22px;background:rgba(61,220,151,0.10);border:1px solid rgba(61,220,151,0.24);">
              <div style="font-size:12px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#b8f4d6;margin-bottom:8px;">Siguiente paso</div>
              <p style="margin:0;color:#e8f2f8;line-height:1.7;font-size:14px;">
                Abre la app, inicia sesion con tu correo asignado y empieza a explorar tu operacion. Cada ruta nueva es una oportunidad para avanzar con orden, enfoque y confianza.
              </p>
            </div>
            <p style="margin:18px 0 0;color:#8f96a1;font-size:12px;line-height:1.6;">
              Gracias por formar parte de AtoB. Esta bienvenida solo se envia una vez por cuenta.
            </p>
          </div>
        </div>
      `,
    },
  });

  if (response.statusCode < 200 || response.statusCode >= 300) {
    const resendMessage =
      response.json?.message ||
      response.json?.error?.message ||
      response.raw ||
      "Error desconocido de Resend";
    throw new Error(`Resend: ${resendMessage}`);
  }

  return {
    sent: true,
    provider: "resend",
    messageId: response.json?.id || null,
  };
}

async function sendWelcomeEmail({ profile }) {
  const safeName = escapeHtml(profile.displayName || "Driver");
  const safeEmail = escapeHtml(profile.email || "");
  if (hasResendConfig()) {
    return sendWelcomeEmailWithResend({
      profile,
      safeName,
      safeEmail,
    });
  }
  const transporter = getInviteTransporter();
  if (!transporter) {
    throw new Error(
      "No hay proveedor de correo configurado en Render. Agrega SMTP_* o RESEND_API_KEY + RESEND_FROM_EMAIL.",
    );
  }
  await transporter.sendMail({
    from: `"${SMTP_FROM_NAME}" <${SMTP_FROM_EMAIL}>`,
    to: profile.email,
    subject: "Bienvenido a AtoB: tu cuenta ya esta activa",
    text:
      `Hola ${profile.displayName}.\n\n` +
      `Tu cuenta de AtoB ya quedo activada correctamente.\n` +
      `Correo asignado: ${profile.email}\n\n` +
      `Nos alegra tenerte dentro. Ya puedes abrir la app, iniciar sesion y empezar tu ruta con una operacion clara, segura y profesional.\n\n` +
      `Bienvenido a bordo.\nAtoB Dispatch`,
    html: `
      <div style="margin:0;padding:32px 18px;background:#050607;color:#f4f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
        <div style="max-width:640px;margin:0 auto;background:radial-gradient(circle at top left, rgba(61,220,151,0.20), transparent 38%),linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02));border:1px solid rgba(255,255,255,0.08);border-radius:34px;padding:32px;box-shadow:0 34px 90px rgba(0,0,0,0.42);">
          <div style="display:inline-grid;place-items:center;width:68px;height:68px;border-radius:22px;background:linear-gradient(135deg,#3DDC97,#72BBFF);color:#071018;font-weight:900;font-size:28px;box-shadow:0 20px 46px rgba(61,220,151,0.26);">A2</div>
          <div style="margin-top:16px;display:inline-block;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);font-size:12px;font-weight:800;color:#d8e5ef;">Welcome to AtoB</div>
          <h1 style="margin:18px 0 10px;font-size:34px;line-height:1.02;letter-spacing:-0.03em;">Tu cuenta ya esta activa</h1>
          <p style="margin:0 0 12px;color:#b4bcc7;line-height:1.7;font-size:15px;">
            Hola ${safeName}, tu acceso ya quedo confirmado y listo para usarse. Este es el inicio de una experiencia mas fluida, clara y profesional dentro de AtoB.
          </p>
          <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:20px 0;">
            <div style="padding:16px;border-radius:18px;background:rgba(255,255,255,0.035);border:1px solid rgba(255,255,255,0.08);">
              <div style="font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#8f9baa;margin-bottom:6px;">Estado</div>
              <div style="font-size:16px;font-weight:800;color:#ffffff;">Cuenta activa</div>
            </div>
            <div style="padding:16px;border-radius:18px;background:rgba(255,255,255,0.035);border:1px solid rgba(255,255,255,0.08);">
              <div style="font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#8f9baa;margin-bottom:6px;">Correo asignado</div>
              <div style="font-size:15px;font-weight:700;color:#ffffff;">${safeEmail}</div>
            </div>
          </div>
          <div style="padding:18px;border-radius:22px;background:rgba(61,220,151,0.10);border:1px solid rgba(61,220,151,0.24);">
            <div style="font-size:12px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase;color:#b8f4d6;margin-bottom:8px;">Siguiente paso</div>
            <p style="margin:0;color:#e8f2f8;line-height:1.7;font-size:14px;">
              Abre la app, inicia sesion con tu correo asignado y empieza a explorar tu operacion. Cada ruta nueva es una oportunidad para avanzar con orden, enfoque y confianza.
            </p>
          </div>
          <p style="margin:18px 0 0;color:#8f96a1;font-size:12px;line-height:1.6;">
            Gracias por formar parte de AtoB. Esta bienvenida solo se envia una vez por cuenta.
          </p>
        </div>
      </div>
    `,
  });
  return {
    sent: true,
    provider: "smtp",
  };
}

function resolveDriverAccessHash(profile, candidate) {
  return ensureSecretHash({
    scope: "driver-access",
    identity: profile.id,
    secretOrHash: candidate,
  });
}

function resolveAccountPasswordHash(passwordIdentity, candidate) {
  return ensureSecretHash({
    scope: "account",
    identity: passwordIdentity,
    secretOrHash: candidate,
  });
}

function resolveAccountPasswordIdentity({
  accountKey,
  role,
  user,
  passwordIdentity,
}) {
  if (asString(role, "driver") === "admin") {
    return FIXED_ADMIN_CREDENTIAL_ID;
  }
  return asString(passwordIdentity, asString(user?.id, accountKey));
}

function sanitizeDriverAccess(profile) {
  const id = asString(profile.id);
  const email = normalizeEmail(profile.email);
  const rawAccessCode = asString(profile.accessCode);
  const isActivated = profile.isActivated === false ? false : true;
  return {
    id,
    displayName: asString(profile.displayName),
    email,
    accessCode: id
      ? resolveDriverAccessHash({ id, email }, rawAccessCode)
      : rawAccessCode,
    accessCodeTail: asString(
      profile.accessCodeTail,
      isSecureHash(rawAccessCode) ? "" : secretTail(rawAccessCode),
    ),
    phoneNumber: asString(profile.phoneNumber, null),
    governmentId: asString(profile.governmentId, null),
    isActive: profile.isActive !== false,
    isActivated,
    activationTokenHash: asString(profile.activationTokenHash),
    activationSentAt: asString(profile.activationSentAt, null),
    activatedAt: isActivated
      ? asString(profile.activatedAt, nowIso())
      : asString(profile.activatedAt, null),
    welcomeSentAt: asString(profile.welcomeSentAt, null),
    createdAt: asString(profile.createdAt, nowIso()),
  };
}

function listDriverAccessProfiles() {
  return Array.from(driverAccessProfiles.values())
    .map((profile) => sanitizeDriverAccess(profile))
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

function loadDriverAccessProfiles() {
  try {
    if (!fs.existsSync(ACCESS_STORE_PATH)) return;
    const raw = fs.readFileSync(ACCESS_STORE_PATH, "utf8");
    if (!raw.trim()) return;
    const decoded = JSON.parse(raw);
    if (!Array.isArray(decoded)) return;
    driverAccessProfiles.clear();
    decoded.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const profile = sanitizeDriverAccess(item);
      if (!profile.id || !profile.email) return;
      driverAccessProfiles.set(profile.id, profile);
    });
  } catch (error) {
    console.log(`access-store load failed: ${error.message || error}`);
  }
}

function persistDriverAccessProfiles() {
  try {
    fs.writeFileSync(
      ACCESS_STORE_PATH,
      JSON.stringify(listDriverAccessProfiles(), null, 2),
      "utf8",
    );
  } catch (error) {
    console.log(`access-store save failed: ${error.message || error}`);
  }
}

function sanitizeUserProfile(raw, fallbackRole = "driver") {
  const user = raw && typeof raw === "object" ? raw : {};
  return {
    id: asString(user.id),
    name: asString(user.name),
    role: asString(user.role, fallbackRole),
    legalName: asString(user.legalName, user.name),
    email: normalizeEmail(user.email),
    phoneNumber: asString(user.phoneNumber),
    address: asString(user.address),
    governmentId: asString(user.governmentId),
    languageCode: asString(user.languageCode, "es"),
    mapThemeMode: asString(user.mapThemeMode, "flow"),
    isOnline: user.isOnline !== false,
    avatarPath: asString(user.avatarPath, ""),
    vehicleMake: asString(user.vehicleMake),
    vehicleModel: asString(user.vehicleModel),
    vehicleColor: asString(user.vehicleColor),
    vehiclePlate: asString(user.vehiclePlate),
    vehicleYear: asString(user.vehicleYear),
  };
}

function sanitizeAccountProfile(record) {
  const fallbackRole = asString(record?.role, "driver");
  const user = sanitizeUserProfile(record?.user, fallbackRole);
  const accountKey = asString(record?.accountKey);
  const passwordIdentity = resolveAccountPasswordIdentity({
    accountKey,
    role: fallbackRole,
    user,
    passwordIdentity: record?.passwordIdentity,
  });
  return {
    accountKey,
    role: fallbackRole,
    passwordIdentity,
    password: resolveAccountPasswordHash(
      passwordIdentity,
      asString(record?.password),
    ),
    passwordUpdatedAt: asString(record?.passwordUpdatedAt, nowIso()),
    savedAt: asString(record?.savedAt, nowIso()),
    driverAccessSnapshot:
      record?.driverAccessSnapshot &&
      typeof record.driverAccessSnapshot === "object"
        ? sanitizeDriverAccess(record.driverAccessSnapshot)
        : null,
    authorizedDriversBackup: Array.isArray(record?.authorizedDriversBackup)
      ? record.authorizedDriversBackup
          .filter((item) => item && typeof item === "object")
          .map((item) => sanitizeDriverAccess(item))
      : [],
    authorizedDriversUpdatedAt: asString(
      record?.authorizedDriversUpdatedAt,
      null,
    ),
    user,
  };
}

function recoverDriverAccessProfilesFromAccounts() {
  let changed = false;
  for (const record of accountProfiles.values()) {
    if (!record || asString(record.role, "driver") !== "driver") continue;
    const snapshot =
      record.driverAccessSnapshot && typeof record.driverAccessSnapshot === "object"
        ? sanitizeDriverAccess(record.driverAccessSnapshot)
        : sanitizeDriverAccess({
            id: asString(record.user?.id, record.passwordIdentity || record.accountKey),
            displayName: asString(record.user?.legalName, record.user?.name),
            email: normalizeEmail(record.user?.email),
            accessCode: asString(record.password),
            accessCodeTail: "",
            phoneNumber: asString(record.user?.phoneNumber, null),
            governmentId: asString(record.user?.governmentId, null),
            isActive: true,
            isActivated: true,
            activatedAt: asString(record.savedAt, nowIso()),
            createdAt: asString(record.savedAt, nowIso()),
          });
    if (!snapshot.id || !snapshot.email || !snapshot.accessCode) continue;

    let existingId = null;
    for (const [profileId, profile] of driverAccessProfiles.entries()) {
      if (
        profileId === snapshot.id ||
        normalizeEmail(profile.email) === normalizeEmail(snapshot.email)
      ) {
        existingId = profileId;
        break;
      }
    }

    if (existingId) {
      const current = driverAccessProfiles.get(existingId);
      const merged = sanitizeDriverAccess({
        ...snapshot,
        ...current,
        id: existingId,
        email: normalizeEmail(current?.email || snapshot.email),
        accessCode: asString(current?.accessCode, snapshot.accessCode),
        accessCodeTail: asString(current?.accessCodeTail, snapshot.accessCodeTail),
        phoneNumber: asString(current?.phoneNumber, snapshot.phoneNumber),
        governmentId: asString(current?.governmentId, snapshot.governmentId),
        isActive: current?.isActive !== false,
        isActivated: current?.isActivated === true || snapshot.isActivated === true,
        activationTokenHash: asString(current?.activationTokenHash),
        activationSentAt: asString(current?.activationSentAt, snapshot.activationSentAt),
        activatedAt: asString(current?.activatedAt, snapshot.activatedAt),
        welcomeSentAt: asString(current?.welcomeSentAt, snapshot.welcomeSentAt),
        createdAt: asString(current?.createdAt, snapshot.createdAt),
      });
      driverAccessProfiles.set(existingId, merged);
      continue;
    }

    driverAccessProfiles.set(snapshot.id, snapshot);
    changed = true;
  }

  if (changed) {
    persistDriverAccessProfiles();
  }
  return changed;
}

function recoverDriverAccessProfilesFromAdminBackups() {
  let changed = false;
  for (const record of accountProfiles.values()) {
    if (!record || asString(record.role, "driver") !== "admin") continue;
    const backup = Array.isArray(record.authorizedDriversBackup)
      ? record.authorizedDriversBackup
      : [];
    for (const item of backup) {
      const snapshot = sanitizeDriverAccess(item);
      if (!snapshot.id || !snapshot.email || !snapshot.accessCode) continue;
      const exists = Array.from(driverAccessProfiles.values()).some(
        (profile) =>
          profile.id === snapshot.id ||
          normalizeEmail(profile.email) === normalizeEmail(snapshot.email),
      );
      if (exists) continue;
      driverAccessProfiles.set(snapshot.id, snapshot);
      changed = true;
    }
  }
  if (changed) {
    persistDriverAccessProfiles();
  }
  return changed;
}

function loadAccountProfiles() {
  try {
    if (!fs.existsSync(ACCOUNT_STORE_PATH)) return;
    const raw = fs.readFileSync(ACCOUNT_STORE_PATH, "utf8");
    if (!raw.trim()) return;
    const decoded = JSON.parse(raw);
    if (!Array.isArray(decoded)) return;
    accountProfiles.clear();
    decoded.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const profile = sanitizeAccountProfile(item);
      if (!profile.accountKey) return;
      accountProfiles.set(profile.accountKey, profile);
    });
  } catch (error) {
    console.log(`account-store load failed: ${error.message || error}`);
  }
}

function persistAccountProfiles() {
  try {
    fs.writeFileSync(
      ACCOUNT_STORE_PATH,
      JSON.stringify(Array.from(accountProfiles.values()), null, 2),
      "utf8",
    );
  } catch (error) {
    console.log(`account-store save failed: ${error.message || error}`);
  }
}

function ensureFixedAdminAccountProfile() {
  const accountKey = `admin:${FIXED_ADMIN_EMAIL}`;
  const current = sanitizeAccountProfile(accountProfiles.get(accountKey) || {
    accountKey,
    role: "admin",
  });
  const next = sanitizeAccountProfile({
    ...current,
    accountKey,
    role: "admin",
    passwordIdentity: FIXED_ADMIN_CREDENTIAL_ID,
    password: FIXED_ADMIN_PASSWORD_HASH,
    passwordUpdatedAt: current.passwordUpdatedAt || nowIso(),
    savedAt: nowIso(),
    user: {
      ...current.user,
      id: asString(current.user?.id, "adm_dispatch_primary"),
      name: asString(current.user?.name, "Admin"),
      legalName: asString(current.user?.legalName, "Admin Dispatch"),
      role: "admin",
      email: FIXED_ADMIN_EMAIL,
      phoneNumber: asString(current.user?.phoneNumber, "+1 804 555 1200"),
      address: asString(current.user?.address, "Virginia dispatch lane"),
      governmentId: asString(current.user?.governmentId, "ADM-PRIMARY"),
      languageCode: asString(current.user?.languageCode, "es"),
      mapThemeMode: asString(current.user?.mapThemeMode, "flow"),
      avatarPath: asString(current.user?.avatarPath, ""),
      isOnline: true,
    },
  });
  accountProfiles.set(accountKey, next);
}

function hasAgoraTokenConfig() {
  return Boolean(AGORA_APP_ID && AGORA_APP_CERTIFICATE);
}

function hasLiveKitConfig() {
  return Boolean(LIVEKIT_URL && LIVEKIT_API_KEY && LIVEKIT_API_SECRET);
}

function normalizeAgoraRole(value) {
  return asString(value, "publisher").toLowerCase() === "subscriber"
    ? RtcRole.SUBSCRIBER
    : RtcRole.PUBLISHER;
}

function buildAgoraRtcToken({ channelId, uid, role }) {
  const privilegeExpiredTs =
    Math.floor(Date.now() / 1000) + AGORA_TOKEN_TTL_SECONDS;
  const token = RtcTokenBuilder.buildTokenWithUid(
    AGORA_APP_ID,
    AGORA_APP_CERTIFICATE,
    channelId,
    uid,
    role,
    privilegeExpiredTs,
  );
  return {
    token,
    expiresAt: privilegeExpiredTs,
    ttlSeconds: AGORA_TOKEN_TTL_SECONDS,
  };
}

async function buildLiveKitToken({ roomName, identity, name, role }) {
  const accessToken = new AccessToken(
    LIVEKIT_API_KEY,
    LIVEKIT_API_SECRET,
    {
      identity,
      name,
      ttl: LIVEKIT_TOKEN_TTL,
      metadata: JSON.stringify({
        role,
        identity,
        name,
      }),
    },
  );
  accessToken.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish: true,
    canSubscribe: true,
    canPublishData: true,
  });

  return await accessToken.toJwt();
}

function emitDriversList() {
  io.emit("drivers:list", Array.from(drivers.values()));
}

function resolveIntercomId(data, fallback = "") {
  return asString(
    data?.intercomId || data?.userId || data?.appUserId,
    fallback,
  );
}

function resolveDriverSocketIds(driverId, driverIntercomId = "") {
  const targetId = asString(driverId);
  const intercomId = asString(driverIntercomId);
  const ids = new Set();

  if (targetId && drivers.has(targetId)) {
    ids.add(targetId);
  }

  for (const [socketId, driver] of drivers.entries()) {
    if (!driver || typeof driver !== "object") continue;
    if (targetId && (driver.id === targetId || driver.intercomId === targetId)) {
      ids.add(socketId);
    }
    if (intercomId && driver.intercomId === intercomId) {
      ids.add(socketId);
    }
  }

  if (!ids.size && targetId) {
    ids.add(targetId);
  }

  return Array.from(ids);
}

function ensureDriverRecord(socketId, name = "Driver") {
  const existing = drivers.get(socketId);
  if (existing) return existing;

  const next = {
    id: socketId,
    intercomId: socketId,
    name,
    role: "driver",
    isOnline: true,
    status: "Disponible (Visible)",
    currentTripId: null,
    location: { latitude: 0, longitude: 0, speed: 0, timestamp: null },
    updatedAt: nowIso(),
  };
  drivers.set(socketId, next);
  return next;
}

function registerClient(socket, data) {
  const role = asString(data?.role).toLowerCase();
  const name = asString(data?.name, role === "admin" ? "Admin" : "Driver");
  const intercomId = role === "admin"
    ? "admin"
    : resolveIntercomId(data, socket.id);

  socket.data.role = role;
  socket.data.name = name;
  socket.data.userId = socket.id;
  socket.data.intercomId = intercomId;

  console.log(`register: ${role} - ${name} (${socket.id})`);

  if (role === "admin") {
    admins.add(socket.id);
    socket.emit("admin:connected");
    socket.emit("drivers:list", Array.from(drivers.values()));
    return;
  }

  if (role === "driver") {
    const existing = ensureDriverRecord(socket.id, name);
    const next = {
      ...existing,
      id: socket.id,
      intercomId,
      name,
      role: "driver",
      isOnline: true,
      email: asString(data?.email, existing.email || ""),
      phoneNumber: asString(data?.phoneNumber, existing.phoneNumber || ""),
      address: asString(data?.address, existing.address || ""),
      governmentId: asString(data?.governmentId, existing.governmentId || ""),
      avatarPath: asString(data?.avatarPath, existing.avatarPath || ""),
      vehicleMake: asString(data?.vehicleMake, existing.vehicleMake || ""),
      vehicleModel: asString(data?.vehicleModel, existing.vehicleModel || ""),
      vehicleColor: asString(data?.vehicleColor, existing.vehicleColor || ""),
      vehiclePlate: asString(data?.vehiclePlate, existing.vehiclePlate || ""),
      vehicleYear: asString(data?.vehicleYear, existing.vehicleYear || ""),
      updatedAt: nowIso(),
    };
    drivers.set(socket.id, next);
    emitDriversList();
  }
}

function normalizeTripPayload(raw, fallbackDriverId) {
  const sourceTrip =
    raw && typeof raw.trip === "object" && !Array.isArray(raw.trip)
      ? raw.trip
      : null;
  const base = sourceTrip || raw || {};
  const id = asString(base.id || raw?.tripId, `${Date.now()}`);
  const requestedDriverId = asString(
    base.driverId || base.toDriverId || base.targetId || fallbackDriverId,
    "",
  );
  const driverIntercomId = asString(
    base.driverIntercomId ||
      raw?.driverIntercomId ||
      raw?.intercomId ||
      requestedDriverId,
    "",
  );
  if (!requestedDriverId && !driverIntercomId) return null;
  const socketTargets = resolveDriverSocketIds(
    requestedDriverId,
    driverIntercomId,
  );
  const driverId = socketTargets[0] || requestedDriverId || driverIntercomId;

  const existing = trips.get(id);
  const merged = {
    id,
    driverId,
    driverIntercomId,
    origin: asString(base.origin, existing?.origin || "Origen"),
    destination: asString(base.destination, existing?.destination || "Destino"),
    status: asString(base.status, existing?.status || "assigned"),
    createdAt: asString(base.createdAt, existing?.createdAt || nowIso()),
    distanceMiles: asNumber(base.distanceMiles, existing?.distanceMiles || 0),
    durationMinutes: asNumber(base.durationMinutes, existing?.durationMinutes || 0),
    fareUsd: asNumber(base.fareUsd, existing?.fareUsd || 0),
    routePoints: Array.isArray(base.routePoints)
      ? base.routePoints
      : existing?.routePoints || [],
    originLocation: base.originLocation || existing?.originLocation || null,
    destinationLocation:
      base.destinationLocation || existing?.destinationLocation || null,
    updatedAt: nowIso(),
  };

  trips.set(id, merged);
  return merged;
}

function emitTripAssigned(trip) {
  const socketTargets = resolveDriverSocketIds(
    trip.driverId,
    trip.driverIntercomId,
  );
  socketTargets.forEach((socketId) => {
    io.to(socketId).emit("trip:assigned", trip);
  });
  admins.forEach((adminId) => io.to(adminId).emit("trip:assigned", trip));
}

function updateDriverFromTrip(trip) {
  const socketTargets = resolveDriverSocketIds(
    trip.driverId,
    trip.driverIntercomId,
  );
  socketTargets.forEach((socketId) => {
    const record = ensureDriverRecord(socketId, "Driver");
    drivers.set(socketId, {
      ...record,
      status: asString(record.status, "Disponible (Visible)"),
      currentTripId:
        trip.status === "rejected" || trip.status === "completed" ? null : trip.id,
      isOnline: true,
      updatedAt: nowIso(),
    });
  });
  emitDriversList();
}

function handleTripAssignment(raw) {
  const trip = normalizeTripPayload(raw);
  if (!trip) return;

  trip.status = "assigned";
  trip.updatedAt = nowIso();
  trips.set(trip.id, trip);

  updateDriverFromTrip(trip);
  emitTripAssigned(trip);
  io.emit("trip:update", trip);
}

function handleTripDecision(raw, status) {
  const tripId = asString(raw?.tripId || raw?.id);
  if (!tripId) return;

  const existing = trips.get(tripId);
  if (!existing) return;

  const next = {
    ...existing,
    status,
    updatedAt: nowIso(),
  };
  trips.set(tripId, next);
  updateDriverFromTrip(next);

  io.emit(`trip:${status}`, {
    tripId: next.id,
    driverId: next.driverId,
    status: next.status,
  });
  io.emit("trip:update", next);

  if (status === "rejected") {
    const socketTargets = resolveDriverSocketIds(
      next.driverId,
      next.driverIntercomId,
    );
    socketTargets.forEach((socketId) => {
      const driver = drivers.get(socketId);
      if (!driver) return;
      drivers.set(socketId, {
        ...driver,
        currentTripId: null,
        status: "Disponible",
        updatedAt: nowIso(),
      });
    });
    emitDriversList();
  }
}

function buildVoicePayload(socket, raw) {
  const channel = asString(
    raw?.channel,
    raw?.private || raw?.channelNumber === 2 ? "private" : "global",
  );
  const fromId = asString(raw?.fromId || raw?.senderId, socket.id);
  const fromName = asString(
    raw?.fromName || raw?.senderName,
    socket.data.name || "Usuario",
  );
  const target = asString(raw?.toDriverId || raw?.targetId);

  return {
    channel,
    private: channel === "private",
    channelNumber: channel === "private" ? 2 : 1,
    fromId,
    fromName,
    senderId: fromId,
    senderName: fromName,
    senderRole: asString(raw?.senderRole, socket.data.role || "driver"),
    toDriverId: target || null,
    targetId: target || null,
    sourceSocketId: socket.id,
    clientSessionId: asString(raw?.clientSessionId, null),
  };
}

function isVoiceLockStale() {
  if (!channelBusy || !channelLockedAt) return false;
  return Date.now() - channelLockedAt >= CHANNEL_BUSY_TTL_MS;
}

function releaseVoice(socket, raw, options = {}) {
  const force = options.force === true;
  const callerId = socket?.id || null;

  if (!force && channelBusy && channelOwnerId && callerId !== channelOwnerId) {
    if (!isVoiceLockStale()) {
      return;
    }
  }

  channelBusy = false;
  channelOwnerId = null;
  channelLockedAt = 0;

  const payload = raw && typeof raw === "object" ? raw : {};
  io.emit("voice:stop", payload);
  io.emit("voice:end", payload);
  console.log("voice:stop");
}

function routeVoiceStart(socket, raw) {
  const payload = buildVoicePayload(socket, raw);
  const requesterId = socket.id;

  if (channelBusy && channelOwnerId && channelOwnerId !== requesterId) {
    if (isVoiceLockStale()) {
      releaseVoice(socket, { reason: "stale-lock-cleared" }, { force: true });
    } else {
      console.log("channel busy, ignoring voice:start");
      return;
    }
  }

  channelBusy = true;
  channelOwnerId = requesterId;
  channelLockedAt = Date.now();
  console.log(`voice:start -> ${payload.channel} from ${payload.fromName}`);

  if (payload.channel === "private") {
    if (payload.toDriverId) {
      if (payload.toDriverId.toLowerCase() === "admin") {
        admins.forEach((adminId) => io.to(adminId).emit("voice:start", payload));
      } else {
        io.to(payload.toDriverId).emit("voice:start", payload);
      }
    }
    io.to(socket.id).emit("voice:start", payload);
    return;
  }

  io.emit("voice:start", payload);
}

function routeVoiceChunk(socket, raw) {
  const mapPayload =
    raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  const channel = asString(
    mapPayload?.channel,
    mapPayload?.private || mapPayload?.channelNumber === 2 ? "private" : "global",
  );
  const target = asString(mapPayload?.toDriverId || mapPayload?.targetId);

  if (channelBusy && channelOwnerId && channelOwnerId !== socket.id) {
    return;
  }

  if (channel === "private" && target) {
    if (target.toLowerCase() === "admin") {
      admins.forEach((adminId) => io.to(adminId).emit("voice:chunk", raw));
    } else {
      io.to(target).emit("voice:chunk", raw);
    }
    return;
  }

  io.emit("voice:chunk", raw);
}

function buildChatPayload(socket, raw) {
  const senderRole = asString(raw?.senderRole, socket.data.role || "driver");
  const senderId = asString(
    raw?.senderId,
    senderRole === "admin" ? "admin" : socket.id,
  );
  const senderName = asString(raw?.senderName, socket.data.name || "Usuario");
  const chatScope = asString(raw?.chatScope, "private").toLowerCase();
  const groupConversation = "fleet::global";
  if (chatScope === "global" || asString(raw?.conversationId) === groupConversation) {
    return {
      id: asString(raw?.id, `${Date.now()}`),
      conversationId: groupConversation,
      senderId,
      senderName,
      senderRole,
      targetId: "all",
      driverId: asString(raw?.driverId, senderRole === "driver" ? socket.id : ""),
      text: asString(raw?.text),
      imageBase64: asString(raw?.imageBase64, null),
      imageMimeType: asString(raw?.imageMimeType, null),
      createdAt: asString(raw?.createdAt, nowIso()),
      chatScope: "global",
    };
  }

  const targetId = asString(raw?.targetId || raw?.toDriverId);
  const driverId = asString(
    raw?.driverId,
    senderRole === "admin" ? targetId : socket.id,
  );

  if (!driverId) return null;
  if (senderRole === "admin" && !targetId) return null;

  return {
    id: asString(raw?.id, `${Date.now()}`),
    conversationId: asString(raw?.conversationId, `admin::${driverId}`),
    senderId,
    senderName,
    senderRole,
    targetId: senderRole === "admin" ? targetId : "admin",
    driverId,
    text: asString(raw?.text),
    imageBase64: asString(raw?.imageBase64, null),
    imageMimeType: asString(raw?.imageMimeType, null),
    createdAt: asString(raw?.createdAt, nowIso()),
  };
}

function routeChatMessage(socket, raw) {
  const payload = buildChatPayload(socket, raw);
  if (!payload) return;

  if (payload.conversationId === "fleet::global") {
    io.emit("chat:message", payload);
    return;
  }

  if (payload.senderRole === "admin") {
    io.to(payload.targetId).emit("chat:message", payload);
    admins.forEach((adminId) => io.to(adminId).emit("chat:message", payload));
    return;
  }

  admins.forEach((adminId) => io.to(adminId).emit("chat:message", payload));
  io.to(socket.id).emit("chat:message", payload);
}

loadDriverAccessProfiles();
persistDriverAccessProfiles();
loadAccountProfiles();
ensureFixedAdminAccountProfile();
persistAccountProfiles();
recoverDriverAccessProfilesFromAccounts();
recoverDriverAccessProfilesFromAdminBackups();

io.on("connection", (socket) => {
  console.log(`client connected: ${socket.id}`);

  socket.on("register", (data) => registerClient(socket, data || {}));

  socket.on("admin:connect", (data) => {
    registerClient(socket, { ...(data || {}), role: "admin" });
  });

  socket.on("driver:connect", (data) => {
    registerClient(socket, {
      ...(data || {}),
      role: "driver",
      name: asString(data?.name, "Driver"),
    });
  });

  socket.on("drivers:request", () => {
    socket.emit("drivers:list", Array.from(drivers.values()));
  });

  // Backward compatibility with older clients.
  socket.on("drivers:list", () => {
    socket.emit("drivers:list", Array.from(drivers.values()));
  });

  socket.on("driver:location:update", (data) => {
    const fromDriverSocket = socket.data.role === "driver";
    const driverId = fromDriverSocket
      ? socket.id
      : asString(data?.driverId, socket.id);
    const name = asString(data?.name, socket.data.name || "Driver");
    const status = asString(data?.status, "Disponible (Visible)");
    const base = ensureDriverRecord(driverId, name);
    const nextTripId = data?.currentTripId === null
      ? null
      : asString(data?.currentTripId, base.currentTripId || "");
    const next = {
      ...base,
      id: driverId,
      intercomId: resolveIntercomId(data, base.intercomId || driverId),
      name,
      role: "driver",
      isOnline: true,
      status,
      currentTripId: nextTripId || null,
      email: asString(data?.email, base.email || ""),
      phoneNumber: asString(data?.phoneNumber, base.phoneNumber || ""),
      address: asString(data?.address, base.address || ""),
      governmentId: asString(data?.governmentId, base.governmentId || ""),
      avatarPath: asString(data?.avatarPath, base.avatarPath || ""),
      vehicleMake: asString(data?.vehicleMake, base.vehicleMake || ""),
      vehicleModel: asString(data?.vehicleModel, base.vehicleModel || ""),
      vehicleColor: asString(data?.vehicleColor, base.vehicleColor || ""),
      vehiclePlate: asString(data?.vehiclePlate, base.vehiclePlate || ""),
      vehicleYear: asString(data?.vehicleYear, base.vehicleYear || ""),
      location: normalizeLocation(data),
      updatedAt: nowIso(),
    };

    drivers.set(driverId, next);
    io.emit("driver:location:update", {
      driverId: next.id,
      intercomId: next.intercomId,
      name: next.name,
      status: next.status,
      currentTripId: next.currentTripId || null,
      vehicleMake: next.vehicleMake,
      vehicleModel: next.vehicleModel,
      vehicleColor: next.vehicleColor,
      vehiclePlate: next.vehiclePlate,
      vehicleYear: next.vehicleYear,
      ...next.location,
    });
    emitDriversList();
  });

  socket.on("driver:location", (data) => {
    socket.emit("driver:location:update", data);
  });

  socket.on("assign:trip", (data) => handleTripAssignment(data || {}));
  socket.on("trip:assigned", (data) => handleTripAssignment(data || {}));
  socket.on("trip:accepted", (data) => handleTripDecision(data || {}, "accepted"));
  socket.on("trip:rejected", (data) => handleTripDecision(data || {}, "rejected"));
  socket.on("chat:send", (data) => routeChatMessage(socket, data || {}));

  socket.on("voice:start", (data) => routeVoiceStart(socket, data || {}));
  socket.on("voice:chunk", (data) => routeVoiceChunk(socket, data));
  socket.on("voice:stop", (data) => releaseVoice(socket, data || {}));
  socket.on("voice:end", (data) => releaseVoice(socket, data || {}));

  socket.on("disconnect", () => {
    console.log(`client disconnected: ${socket.id}`);

    if (channelOwnerId === socket.id) {
      releaseVoice(socket, { fromId: socket.id, reason: "disconnect" }, { force: true });
    }

    admins.delete(socket.id);
    if (drivers.has(socket.id)) {
      drivers.delete(socket.id);
      emitDriversList();
    }
  });
});

app.get("/", (_, res) => {
  res.status(200).send("AtoB server online");
});

app.get("/access/drivers", (_, res) => {
  recoverDriverAccessProfilesFromAccounts();
  recoverDriverAccessProfilesFromAdminBackups();
  res.status(200).json({
    ok: true,
    drivers: listDriverAccessProfiles(),
  });
});

app.post("/access/drivers/upsert", (req, res) => {
  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const id = asString(payload.id, `${Date.now()}`);
  const email = normalizeEmail(payload.email);
  const displayName = asString(payload.displayName);
  const accessCode = asString(payload.accessCode);
  const accessCodeTail = asString(payload.accessCodeTail);
  if (!displayName || !email) {
    res.status(400).json({
      ok: false,
      message: "displayName y email son obligatorios",
    });
    return;
  }

  let existingId = null;
  for (const [profileId, profile] of driverAccessProfiles.entries()) {
    if (profileId === id || normalizeEmail(profile.email) === email) {
      existingId = profileId;
      break;
    }
  }

  const current = existingId ? driverAccessProfiles.get(existingId) : null;
  const resolvedId = existingId || id;
  const skipInvite = payload.skipInvite === true;
  const forceInvite = payload.forceInvite === true;
  const resolvedAccessCode = accessCode || current?.accessCode || "";
  if (!resolvedAccessCode) {
    res.status(400).json({
      ok: false,
      message: "accessCode es obligatorio para crear o actualizar acceso",
    });
    return;
  }
  const shouldSendInvite =
    !skipInvite &&
    (
      !current ||
      (
        current.isActivated !== true &&
        (
          forceInvite ||
          !current.activationSentAt ||
          !current.activationTokenHash
        )
      )
    );
  const activationToken = shouldSendInvite
    ? crypto.randomBytes(24).toString("hex")
    : null;
  const nextActivationHash = activationToken
    ? activationTokenHash(resolvedId, activationToken)
    : current?.activationTokenHash || "";
  const activationUrl = activationToken ? buildActivationUrl(activationToken) : null;
  const passwordChanged = resolvedAccessCode !== (current?.accessCode || "");
  const next = sanitizeDriverAccess({
    id: resolvedId,
    displayName,
    email,
    accessCode: resolvedAccessCode,
    accessCodeTail: accessCodeTail || current?.accessCodeTail || "",
    phoneNumber: asString(payload.phoneNumber, current?.phoneNumber || null),
    governmentId: asString(payload.governmentId, current?.governmentId || null),
    isActive: payload.isActive === false ? false : current?.isActive !== false,
    isActivated:
      current?.isActivated === true || payload.isActivated === true,
    activationTokenHash: nextActivationHash,
    activationSentAt: shouldSendInvite
      ? nowIso()
      : current?.activationSentAt ||
        asString(payload.activationSentAt, null),
    activatedAt:
      current?.activatedAt || asString(payload.activatedAt, null),
    welcomeSentAt:
      current?.welcomeSentAt || asString(payload.welcomeSentAt, null),
    createdAt: current?.createdAt || nowIso(),
  });
  driverAccessProfiles.set(next.id, next);
  persistDriverAccessProfiles();
  const accountKey = `driver:${email}`;
  const currentAccount = accountProfiles.get(accountKey);
  const nextAccount = sanitizeAccountProfile({
    accountKey,
    role: "driver",
    passwordIdentity: next.id,
    password: next.accessCode,
    passwordUpdatedAt:
      passwordChanged || !currentAccount?.passwordUpdatedAt
        ? nowIso()
        : currentAccount.passwordUpdatedAt,
    savedAt: nowIso(),
    driverAccessSnapshot: next,
    user: {
      ...(currentAccount?.user || {}),
      id: currentAccount?.user?.id || next.id,
      name: currentAccount?.user?.name || displayName,
      legalName: displayName,
      role: "driver",
      email,
      phoneNumber: asString(payload.phoneNumber, currentAccount?.user?.phoneNumber || ""),
      address: asString(currentAccount?.user?.address),
      governmentId: asString(payload.governmentId, currentAccount?.user?.governmentId || ""),
      languageCode: asString(currentAccount?.user?.languageCode, "es"),
      mapThemeMode: asString(currentAccount?.user?.mapThemeMode, "flow"),
      avatarPath: asString(currentAccount?.user?.avatarPath, ""),
      isOnline: currentAccount?.user?.isOnline !== false,
    },
  });
  accountProfiles.set(accountKey, nextAccount);
  persistAccountProfiles();
  if (!shouldSendInvite || !activationUrl) {
    res.status(200).json({
      ok: true,
      profile: next,
      drivers: listDriverAccessProfiles(),
      inviteEmailSent: false,
      inviteQueued: false,
      inviteSkipped: true,
      activationUrl: null,
    });
    return;
  }
  res.status(200).json({
    ok: true,
    profile: next,
    drivers: listDriverAccessProfiles(),
    inviteEmailSent: false,
    inviteQueued: true,
    inviteSkipped: false,
    activationUrl,
  });
  Promise.resolve(sendInviteEmail({ profile: next, activationUrl })).catch((error) => {
    console.log(`invite-email failed: ${error.message || error}`);
  });
});

app.post("/access/drivers/toggle", (req, res) => {
  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const id = asString(payload.id);
  if (!id || !driverAccessProfiles.has(id)) {
    res.status(404).json({ ok: false, message: "Acceso no encontrado" });
    return;
  }
  const current = driverAccessProfiles.get(id);
  const next = sanitizeDriverAccess({
    ...current,
    isActive: payload.isActive !== false,
  });
  driverAccessProfiles.set(id, next);
  persistDriverAccessProfiles();
  const profileAccountKey = `driver:${normalizeEmail(next.email)}`;
  const currentAccount = accountProfiles.get(profileAccountKey);
  if (currentAccount) {
    accountProfiles.set(
      profileAccountKey,
      sanitizeAccountProfile({
        ...currentAccount,
        savedAt: nowIso(),
        driverAccessSnapshot: next,
      }),
    );
    persistAccountProfiles();
  }
  res.status(200).json({ ok: true, profile: next, drivers: listDriverAccessProfiles() });
});

app.post("/access/drivers/approve", (req, res) => {
  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const id = asString(payload.id);
  const email = normalizeEmail(payload.email);
  let profile = null;

  if (id && driverAccessProfiles.has(id)) {
    profile = driverAccessProfiles.get(id);
  }
  if (!profile && email) {
    profile = listDriverAccessProfiles().find(
      (item) => normalizeEmail(item.email) === email,
    );
  }

  if (!profile) {
    res.status(404).json({
      ok: false,
      message: "Acceso no encontrado",
    });
    return;
  }

  const next = sanitizeDriverAccess({
    ...profile,
    isActive: true,
    isActivated: true,
    activatedAt: profile.activatedAt || nowIso(),
    activationTokenHash: "",
  });
  driverAccessProfiles.set(next.id, next);
  persistDriverAccessProfiles();
  const profileAccountKey = `driver:${normalizeEmail(next.email)}`;
  const currentAccount = accountProfiles.get(profileAccountKey);
  if (currentAccount) {
    accountProfiles.set(
      profileAccountKey,
      sanitizeAccountProfile({
        ...currentAccount,
        savedAt: nowIso(),
        driverAccessSnapshot: next,
      }),
    );
    persistAccountProfiles();
  }

  const respond = (welcomeSent, welcomeSkipped = false, welcomeError = null) => {
    res.status(200).json({
      ok: true,
      profile: driverAccessProfiles.get(next.id),
      drivers: listDriverAccessProfiles(),
      welcomeEmailSent: welcomeSent,
      welcomeSkipped,
      welcomeError,
    });
  };

  if (next.welcomeSentAt) {
    respond(false, true, null);
    return;
  }

  Promise.resolve(sendWelcomeEmail({ profile: next }))
    .then(() => {
      const welcomed = sanitizeDriverAccess({
        ...next,
        welcomeSentAt: nowIso(),
      });
      driverAccessProfiles.set(welcomed.id, welcomed);
      persistDriverAccessProfiles();
      const welcomedAccount = accountProfiles.get(profileAccountKey);
      if (welcomedAccount) {
        accountProfiles.set(
          profileAccountKey,
          sanitizeAccountProfile({
            ...welcomedAccount,
            savedAt: nowIso(),
            driverAccessSnapshot: welcomed,
          }),
        );
        persistAccountProfiles();
      }
      respond(true, false, null);
    })
    .catch((error) => {
      console.log(`approve-welcome-email failed: ${error.message || error}`);
      respond(false, false, error?.message || String(error));
    });
});

app.post("/access/drivers/remove", (req, res) => {
  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const id = asString(payload.id);
  if (!id) {
    res.status(400).json({ ok: false, message: "id es obligatorio" });
    return;
  }
  driverAccessProfiles.delete(id);
  persistDriverAccessProfiles();
  const accountToRemove = Array.from(accountProfiles.entries()).find(
    ([, record]) =>
      asString(record.role, "driver") === "driver" &&
      sanitizeDriverAccess(record.driverAccessSnapshot || {}).id === id,
  );
  if (accountToRemove) {
    const [accountKey, currentAccount] = accountToRemove;
    accountProfiles.set(
      accountKey,
      sanitizeAccountProfile({
        ...currentAccount,
        savedAt: nowIso(),
        driverAccessSnapshot: null,
      }),
    );
    persistAccountProfiles();
  }
  res.status(200).json({ ok: true, drivers: listDriverAccessProfiles() });
});

app.post("/access/drivers/auth", (req, res) => {
  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const email = normalizeEmail(payload.email);
  const accessCode = asString(payload.accessCode);
  if (!email || !accessCode) {
    res.status(400).json({
      ok: false,
      message: "email y accessCode son obligatorios",
    });
    return;
  }
  const match = listDriverAccessProfiles().find(
    (profile) => profile.isActive && normalizeEmail(profile.email) === email,
  );
  if (!match) {
    res.status(401).json({
      ok: false,
      message: "Acceso invalido",
    });
    return;
  }
  if (!match.isActivated) {
    res.status(403).json({
      ok: false,
      code: "activation_required",
      message: "Debes activar la cuenta desde el correo de invitacion",
    });
    return;
  }
  const candidateHash = resolveDriverAccessHash(match, accessCode);
  if (candidateHash !== match.accessCode) {
    res.status(401).json({
      ok: false,
      message: "Acceso invalido",
    });
    return;
  }
  res.status(200).json({ ok: true, profile: match });
});

app.get("/access/activate", (req, res) => {
  const token = asString(req.query.token);
  if (!token) {
    res.status(400).send(
      renderActivationShell({
        title: "Activacion no disponible",
        accent: "#FF8A9A",
        body: `
          <div class="info">
            <span class="label">Enlace no valido</span>
            <p>El enlace de activacion no es valido o esta incompleto.</p>
          </div>
          <div class="info">
            <span class="label">Que hacer</span>
            <p>Solicita una invitacion nueva desde el panel de administracion.</p>
          </div>
        `,
      }),
    );
    return;
  }

  const profile = listDriverAccessProfiles().find(
    (item) => item.activationTokenHash === activationTokenHash(item.id, token),
  );
  if (!profile) {
    res.status(404).send(
      renderActivationShell({
        title: "Activacion no encontrada",
        accent: "#FF8A9A",
        body: `
          <div class="info">
            <span class="label">Invitacion no encontrada</span>
            <p>Este enlace ya no esta disponible o fue reemplazado por una invitacion mas reciente.</p>
          </div>
          <div class="info">
            <span class="label">Siguiente paso</span>
            <p>Pide a operaciones que vuelva a enviarte una invitacion activa.</p>
          </div>
        `,
      }),
    );
    return;
  }

  if (profile.isActivated) {
    res.status(200).send(
      renderActivationShell({
        title: "Cuenta activada",
        accent: "#72BBFF",
        autoClose: true,
        body: `
          <div class="info">
            <span class="label">Estado actual</span>
            <p>${profile.displayName}, ya puedes volver a AtoB e iniciar sesion con tu correo asignado.</p>
          </div>
          <div class="metrics">
            <div class="metric">
              <span class="label">Correo</span>
              <strong>${profile.email}</strong>
            </div>
            <div class="metric">
              <span class="label">Cuenta</span>
              <strong>Activa</strong>
            </div>
          </div>
          <div class="accent-line"></div>
          <div class="info">
            <span class="label">Estado</span>
            <p>Tu acceso ya esta confirmado en el servidor.</p>
          </div>
        `,
      }),
    );
    return;
  }

  res.status(200).send(
    renderActivationShell({
      title: "Activa tu cuenta",
      body: `
        <div class="info">
          <span class="label">Invitacion lista</span>
          <p>${profile.displayName}, confirma la activacion de tu cuenta para empezar a usar AtoB.</p>
        </div>
        <div class="metrics">
          <div class="metric">
            <span class="label">Correo asignado</span>
            <strong>${profile.email}</strong>
          </div>
          <div class="metric">
            <span class="label">Acceso</span>
            <strong>Privado y manual</strong>
          </div>
        </div>
        <div class="info">
          <span class="label">Antes de continuar</span>
          <ul class="checklist">
            <li>Activa la cuenta desde este enlace unico.</li>
            <li>Despues podras entrar con el correo asignado y la clave temporal.</li>
            <li>Si el enlace caduca, operaciones puede emitir uno nuevo.</li>
          </ul>
        </div>
        <form method="post" action="/access/activate/confirm">
          <input type="hidden" name="token" value="${token}" />
          <button type="submit">Activar cuenta</button>
        </form>
      `,
    }),
  );
});

app.post("/access/activate/confirm", (req, res) => {
  const token = asString(req.body?.token || req.query?.token);
  if (!token) {
    res.status(400).send(
      renderActivationShell({
        title: "Activacion no disponible",
        accent: "#FF8A9A",
        body: `
          <div class="info">
            <span class="label">Token faltante</span>
            <p>No se recibio el token de activacion.</p>
          </div>
          <div class="info">
            <span class="label">Que hacer</span>
            <p>Vuelve al correo de invitacion y abre el enlace completo.</p>
          </div>
        `,
      }),
    );
    return;
  }

  const profile = listDriverAccessProfiles().find(
    (item) => item.activationTokenHash === activationTokenHash(item.id, token),
  );
  if (!profile) {
    res.status(404).send(
      renderActivationShell({
        title: "Invitacion no encontrada",
        accent: "#FF8A9A",
        body: `
          <div class="info">
            <span class="label">Invitacion no disponible</span>
            <p>El enlace ya no es valido o fue reemplazado por una version nueva.</p>
          </div>
          <div class="info">
            <span class="label">Siguiente paso</span>
            <p>Solicita una nueva invitacion desde el panel de admin.</p>
          </div>
        `,
      }),
    );
    return;
  }

  const next = sanitizeDriverAccess({
    ...profile,
    isActivated: true,
    activatedAt: nowIso(),
    activationTokenHash: "",
  });
  driverAccessProfiles.set(next.id, next);
  persistDriverAccessProfiles();
  const profileAccountKey = `driver:${normalizeEmail(next.email)}`;
  const currentAccount = accountProfiles.get(profileAccountKey);
  if (currentAccount) {
    accountProfiles.set(
      profileAccountKey,
      sanitizeAccountProfile({
        ...currentAccount,
        savedAt: nowIso(),
        driverAccessSnapshot: next,
      }),
    );
    persistAccountProfiles();
  }
  const renderActivatedResponse = (welcomeSent) =>
    renderActivationShell({
      title: "Cuenta activada",
      accent: "#41D891",
      autoClose: true,
      body: `
        <div class="metrics">
          <div class="metric">
            <span class="label">Resultado</span>
            <strong>Activacion completada</strong>
          </div>
          <div class="metric">
            <span class="label">Correo</span>
            <strong>${profile.email}</strong>
          </div>
        </div>
        <div class="info">
          <span class="label">Felicidades</span>
          <p>Tu cuenta en AtoB ya quedo activada correctamente.</p>
          <p>Ya puedes volver a la app e iniciar sesion con tu correo asignado.</p>
        </div>
        <div class="accent-line"></div>
        <div class="info">
          <span class="label">Estado</span>
          <p>Activacion completada con exito.</p>
          <p>${welcomeSent ? "Tambien enviamos un correo de bienvenida a tu bandeja." : "Tu bienvenida se esta preparando en segundo plano."}</p>
        </div>
      `,
    });

  if (next.welcomeSentAt) {
    res.status(200).send(renderActivatedResponse(true));
    return;
  }

  Promise.resolve(sendWelcomeEmail({ profile: next }))
    .then(() => {
      const welcomed = sanitizeDriverAccess({
        ...next,
        welcomeSentAt: nowIso(),
      });
      driverAccessProfiles.set(welcomed.id, welcomed);
      persistDriverAccessProfiles();
      const welcomedAccount = accountProfiles.get(profileAccountKey);
      if (welcomedAccount) {
        accountProfiles.set(
          profileAccountKey,
          sanitizeAccountProfile({
            ...welcomedAccount,
            savedAt: nowIso(),
            driverAccessSnapshot: welcomed,
          }),
        );
        persistAccountProfiles();
      }
      res.status(200).send(renderActivatedResponse(true));
    })
    .catch((error) => {
      console.log(`welcome-email failed: ${error.message || error}`);
      res.status(200).send(renderActivatedResponse(false));
    });
});

app.get("/accounts/profile", (req, res) => {
  const accountKey = asString(req.query.accountKey);
  if (!accountKey) {
    res.status(400).json({
      ok: false,
      message: "accountKey es obligatorio",
    });
    return;
  }
  const profile = accountProfiles.get(accountKey);
  if (!profile) {
    res.status(404).json({
      ok: false,
      message: "Perfil no encontrado",
    });
    return;
  }
  res.status(200).json({ ok: true, profile });
});

app.post("/accounts/profile/upsert", (req, res) => {
  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const accountKey = asString(payload.accountKey);
  const incomingUser =
    payload.user && typeof payload.user === "object" ? payload.user : {};
  const role = asString(payload.role, incomingUser.role || "driver");

  if (!accountKey) {
    res.status(400).json({
      ok: false,
      message: "accountKey es obligatorio",
    });
    return;
  }

  const current = accountProfiles.get(accountKey);
  const next = sanitizeAccountProfile({
    accountKey,
    role,
    passwordIdentity: asString(
      payload.passwordIdentity,
      current?.passwordIdentity || "",
    ),
    password: asString(payload.password, current?.password || ""),
    passwordUpdatedAt: asString(
      payload.passwordUpdatedAt,
      current?.passwordUpdatedAt || nowIso(),
    ),
    savedAt: nowIso(),
    authorizedDriversBackup: Array.isArray(payload.authorizedDriversBackup)
      ? payload.authorizedDriversBackup
      : current?.authorizedDriversBackup || [],
    authorizedDriversUpdatedAt: asString(
      payload.authorizedDriversUpdatedAt,
      current?.authorizedDriversUpdatedAt || null,
    ),
    user: {
      ...(current?.user || {}),
      ...incomingUser,
      role,
      email: normalizeEmail(incomingUser.email || current?.user?.email),
    },
  });

  accountProfiles.set(accountKey, next);
  persistAccountProfiles();
  res.status(200).json({ ok: true, profile: next });
});

app.get("/agora/rtc-token", (req, res) => {
  const channelId = asString(req.query.channelId || req.query.channel);
  const uid = Math.trunc(asNumber(req.query.uid, NaN));
  const role = normalizeAgoraRole(req.query.role);

  if (!channelId) {
    res.status(400).json({
      ok: false,
      message: "channelId es obligatorio",
    });
    return;
  }

  if (!Number.isInteger(uid) || uid <= 0) {
    res.status(400).json({
      ok: false,
      message: "uid invalido",
    });
    return;
  }

  if (!hasAgoraTokenConfig()) {
    res.status(503).json({
      ok: false,
      message:
        "Agora seguro activo sin AGORA_APP_CERTIFICATE en servidor. Configura AGORA_APP_ID y AGORA_APP_CERTIFICATE en Render para emitir tokens dinamicos.",
      secure: true,
      appIdConfigured: Boolean(AGORA_APP_ID),
      certificateConfigured: Boolean(AGORA_APP_CERTIFICATE),
    });
    return;
  }

  try {
    const result = buildAgoraRtcToken({ channelId, uid, role });
    res.status(200).json({
      ok: true,
      appId: AGORA_APP_ID,
      channelId,
      uid,
      secure: true,
      ...result,
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: `No se pudo generar token Agora: ${error.message || error}`,
    });
  }
});

app.get("/livekit/token", async (req, res) => {
  const roomName = asString(req.query.roomName, LIVEKIT_ROOM_NAME);
  const identity = asString(req.query.identity);
  const name = asString(req.query.name, identity);
  const role = asString(req.query.role, identity === "admin" ? "admin" : "driver");

  if (!roomName) {
    res.status(400).json({
      ok: false,
      message: "roomName es obligatorio",
    });
    return;
  }

  if (!identity) {
    res.status(400).json({
      ok: false,
      message: "identity es obligatorio",
    });
    return;
  }

  if (!hasLiveKitConfig()) {
    res.status(503).json({
      ok: false,
      message:
        "LiveKit no esta configurado en servidor. Configura LIVEKIT_URL, LIVEKIT_API_KEY y LIVEKIT_API_SECRET.",
      livekitConfigured: false,
      serverUrlConfigured: Boolean(LIVEKIT_URL),
      apiKeyConfigured: Boolean(LIVEKIT_API_KEY),
      apiSecretConfigured: Boolean(LIVEKIT_API_SECRET),
    });
    return;
  }

  try {
    const token = await buildLiveKitToken({
      roomName,
      identity,
      name,
      role,
    });
    res.status(200).json({
      ok: true,
      provider: "livekit",
      roomName,
      identity,
      name,
      role,
      serverUrl: LIVEKIT_URL,
      token,
      ttl: LIVEKIT_TOKEN_TTL,
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: `No se pudo generar token LiveKit: ${error.message || error}`,
    });
  }
});

const port = Number(process.env.PORT || 3000);
server.listen(port, "0.0.0.0", () => {
  console.log(`AtoB server listening on ${port}`);
});
