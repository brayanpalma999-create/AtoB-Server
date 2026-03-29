const express = require("express");
const http = require("http");
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

function normalizeLocation(raw, fallback = { latitude: 19.4326, longitude: -99.1332 }) {
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
    location: { latitude: 19.4326, longitude: -99.1332, speed: 0, timestamp: null },
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

  console.log(`📥 Registro: ${role} - ${name} (${socket.id})`);

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
  const id = asString(raw?.id, `${Date.now()}`);
  const driverId = asString(raw?.driverId || raw?.toDriverId || raw?.targetId, fallbackDriverId || "");
  if (!driverId) return null;

  const existing = trips.get(id);
  const merged = {
    id,
    driverId,
    origin: asString(raw?.origin, existing?.origin || "Origen"),
    destination: asString(raw?.destination, existing?.destination || "Destino"),
    status: asString(raw?.status, existing?.status || "assigned"),
    createdAt: asString(raw?.createdAt, existing?.createdAt || nowIso()),
    distanceMiles: asNumber(raw?.distanceMiles, existing?.distanceMiles || 0),
    durationMinutes: asNumber(raw?.durationMinutes, existing?.durationMinutes || 0),
    fareUsd: asNumber(raw?.fareUsd, existing?.fareUsd || 0),
    routePoints: Array.isArray(raw?.routePoints) ? raw.routePoints : existing?.routePoints || [],
    originLocation: raw?.originLocation || existing?.originLocation || null,
    destinationLocation: raw?.destinationLocation || existing?.destinationLocation || null,
    updatedAt: nowIso(),
  };
  trips.set(id, merged);
  return merged;
}

function emitTripAssigned(trip) {
  io.emit("trip:assigned", trip);
  io.to(trip.driverId).emit("trip:assigned", trip);
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
  trips.set(trip.id, trip);
  updateDriverFromTrip(trip);
  emitTripAssigned(trip);
}

function handleTripDecision(socket, raw, status) {
  const tripId = asString(raw?.tripId);
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
  const channel = asString(raw?.channel, raw?.private || raw?.channelNumber === 2 ? "private" : "global");
  const fromId = asString(raw?.fromId || raw?.senderId, socket.id);
  const fromName = asString(raw?.fromName || raw?.senderName, socket.data.name || "Usuario");
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
    clientSessionId: asString(raw?.clientSessionId, null),
  };
}

function routeVoiceStart(socket, raw) {
  const payload = buildVoicePayload(socket, raw);
  const requesterId = payload.fromId || socket.id;

  if (channelBusy && channelOwnerId && channelOwnerId !== requesterId) {
    console.log("⚠️ Canal ocupado, ignorando voice:start");
    return;
  }

  channelBusy = true;
  channelOwnerId = requesterId;
  console.log(`🎙️ voice:start -> ${payload.channel} desde ${payload.fromName}`);

  if (payload.channel === "private") {
    if (payload.toDriverId) {
      io.to(payload.toDriverId).emit("voice:start", payload);
    }
    if (payload.targetId === "admin") {
      admins.forEach((adminId) => io.to(adminId).emit("voice:start", payload));
    }
    io.to(socket.id).emit("voice:start", payload);
    return;
  }

  io.emit("voice:start", payload);
}

function routeVoiceChunk(socket, raw) {
  const mapPayload = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  const channel = asString(mapPayload?.channel, mapPayload?.private || mapPayload?.channelNumber === 2 ? "private" : "global");
  const target = asString(mapPayload?.toDriverId || mapPayload?.targetId);
  const fromId = asString(mapPayload?.fromId || mapPayload?.senderId, socket.id);

  if (channelOwnerId && channelOwnerId !== fromId) return;

  if (channel === "private" && target) {
    io.to(target).emit("voice:chunk", raw);
    if (target === "admin") {
      admins.forEach((adminId) => io.to(adminId).emit("voice:chunk", raw));
    }
    return;
  }

  io.emit("voice:chunk", raw);
}

function releaseVoice(raw) {
  channelBusy = false;
  channelOwnerId = null;
  io.emit("voice:stop", raw || null);
  io.emit("voice:end", raw || null);
  console.log("🛑 voice:stop");
}

io.on("connection", (socket) => {
  console.log(`🔌 Cliente conectado: ${socket.id}`);

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

  // Backward compatibility with old client.
  socket.on("drivers:list", () => {
    socket.emit("drivers:list", Array.from(drivers.values()));
  });

  socket.on("driver:location:update", (data) => {
    const driverId = asString(data?.driverId, socket.id);
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
  socket.on("trip:accepted", (data) => handleTripDecision(socket, data || {}, "accepted"));
  socket.on("trip:rejected", (data) => handleTripDecision(socket, data || {}, "rejected"));

  socket.on("voice:start", (data) => routeVoiceStart(socket, data || {}));
  socket.on("voice:chunk", (data) => routeVoiceChunk(socket, data));
  socket.on("voice:stop", (data) => releaseVoice(data || {}));
  socket.on("voice:end", (data) => releaseVoice(data || {}));

  socket.on("disconnect", () => {
    console.log(`❌ Cliente desconectado: ${socket.id}`);
    if (channelOwnerId === socket.id) {
      releaseVoice({ fromId: socket.id, reason: "disconnect" });
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

const port = Number(process.env.PORT || 3000);
server.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Servidor AtoB escuchando en puerto ${port}`);
});
