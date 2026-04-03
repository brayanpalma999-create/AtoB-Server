const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { RtcRole, RtcTokenBuilder } = require("agora-token");
const { AccessToken } = require("livekit-server-sdk");
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

app.use(express.json({ limit: "1mb" }));
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
  const text = String(value).trim();
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
    user,
  };
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
  const resolvedAccessCode = accessCode || current?.accessCode || "";
  if (!resolvedAccessCode) {
    res.status(400).json({
      ok: false,
      message: "accessCode es obligatorio para crear o actualizar acceso",
    });
    return;
  }
  const next = sanitizeDriverAccess({
    id: resolvedId,
    displayName,
    email,
    accessCode: resolvedAccessCode,
    accessCodeTail: accessCodeTail || current?.accessCodeTail || "",
    phoneNumber: asString(payload.phoneNumber, current?.phoneNumber || null),
    governmentId: asString(payload.governmentId, current?.governmentId || null),
    isActive: payload.isActive === false ? false : current?.isActive !== false,
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
    passwordUpdatedAt: nowIso(),
    savedAt: nowIso(),
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
  res.status(200).json({
    ok: true,
    profile: next,
    drivers: listDriverAccessProfiles(),
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
  res.status(200).json({ ok: true, profile: next, drivers: listDriverAccessProfiles() });
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
