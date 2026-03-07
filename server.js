const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// Lista de drivers conectados
let drivers = {};
let adminConnected = false;

// Canal ocupado
let channelBusy = false;

io.on("connection", (socket) => {
  console.log(`🔌 Cliente conectado: ${socket.id}`);

  // Registro de usuario
  socket.on("register", (data) => {
    const role = data.role;
    const name = data.name;
    const id = socket.id;

    socket.data.role = role;
    socket.data.name = name;
    socket.data.userId = id;

    console.log(`📥 Registro: ${role} - ${name} (${id})`);

    if (role === "driver") {
      drivers[id] = { id, name };
      io.emit("drivers:list", Object.values(drivers));
    }

    if (role === "admin") {
      adminConnected = true;
      io.emit("admin:connected");
      socket.emit("drivers:list", Object.values(drivers));
    }
  });

  // Admin pide lista manualmente
  socket.on("drivers:request", () => {
    socket.emit("drivers:list", Object.values(drivers));
  });

  // Inicio de transmisión
  socket.on("voice:start", (data) => {
    if (channelBusy) {
      console.log("⚠️ Canal ocupado, ignorando voice:start");
      return;
    }

    channelBusy = true;

    const payload = {
      fromName: data.fromName,
      fromId: data.fromId,
      channel: data.channel,
      toDriverId: data.toDriverId || null
    };

    console.log(`🎙️ voice:start → ${data.channel} desde ${data.fromName}`);

    if (data.channel === "global") {
      io.emit("voice:start", payload);
    }

    if (data.channel === "private") {
      if (data.toDriverId) {
        io.to(data.toDriverId).emit("voice:start", payload);
      }
      io.to(socket.id).emit("voice:start", payload);
    }
  });

  // Envío de audio
  socket.on("voice:chunk", (chunk) => {
    io.emit("voice:chunk", chunk);
  });

  // Fin de transmisión
  socket.on("voice:stop", () => {
    channelBusy = false;
    io.emit("voice:stop");
    console.log("🛑 voice:stop");
  });

  // Desconexión
  socket.on("disconnect", () => {
    console.log(`❌ Cliente desconectado: ${socket.id}`);

    if (socket.data.role === "driver") {
      delete drivers[socket.id];
      io.emit("drivers:list", Object.values(drivers));
    }

    if (socket.data.role === "admin") {
      adminConnected = false;
      io.emit("admin:disconnected");
    }
  });
});

// 🔥 IMPORTANTE: escuchar en TODAS las interfaces
server.listen(3000, "0.0.0.0", () => {
  console.log("🚀 Servidor intercom escuchando en puerto 3000");
});