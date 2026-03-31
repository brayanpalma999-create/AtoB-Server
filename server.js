const express = require("express");
const http = require("http");
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

function toDriverStatusFromTripStatus(status, fallback = "Disponible") {
  const normalized = asString(status).toLowerCase();
  if (normalized === "assigned") return "Asignado";
  if (normalized === "accepted") return "En camino";
  if (normalized === "rejected") return "Disponible";
  return fallback;
}

function ensureDriverRecord(socketId, name = "Driver") {
  const existing = drivers.get(socketId);
  if (existing) return existing;

  const next = {
    id: socketId,
    name,
    role: "driver",
    isOnline: true,
    status: "Disponible",
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

  socket.data.role = role;
  socket.data.name = name;
  socket.data.userId = socket.id;

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
      name,
      role: "driver",
      isOnline: true,
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
  const driverId = asString(
    base.driverId || base.toDriverId || base.targetId || fallbackDriverId,
    "",
  );
  if (!driverId) return null;

  const existing = trips.get(id);
  const merged = {
    id,
    driverId,
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
  io.to(trip.driverId).emit("trip:assigned", trip);
  admins.forEach((adminId) => io.to(adminId).emit("trip:assigned", trip));
}

function updateDriverFromTrip(trip) {
  const record = ensureDriverRecord(trip.driverId, "Driver");
  const nextStatus = toDriverStatusFromTripStatus(trip.status, record.status);
  drivers.set(trip.driverId, {
    ...record,
    status: nextStatus,
    currentTripId: trip.status === "rejected" ? null : trip.id,
    isOnline: true,
    updatedAt: nowIso(),
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
    const driver = drivers.get(next.driverId);
    if (driver) {
      drivers.set(next.driverId, {
        ...driver,
        currentTripId: null,
        status: "Disponible",
        updatedAt: nowIso(),
      });
      emitDriversList();
    }
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
    const status = asString(data?.status, "Disponible");
    const base = ensureDriverRecord(driverId, name);
    const next = {
      ...base,
      id: driverId,
      name,
      role: "driver",
      isOnline: true,
      status,
      location: normalizeLocation(data),
      updatedAt: nowIso(),
    };

    drivers.set(driverId, next);
    io.emit("driver:location:update", {
      driverId: next.id,
      name: next.name,
      status: next.status,
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
