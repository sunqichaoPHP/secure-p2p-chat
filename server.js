/**
 * 信令服务器 —— 仅做"搭桥"，不接触任何聊天内容
 * 
 * 职责：
 *   1. 管理房间（创建/销毁）
 *   2. 转发 WebRTC 信令（SDP / ICE）
 *   3. 转发公钥（用于 ECDH 密钥协商）
 * 
 * 不做的：
 *   - 不存储聊天消息
 *   - 不解密任何内容
 *   - 不存储用户身份信息
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e6,  // 1MB 上限
  pingInterval: 10000,
  pingTimeout: 5000,
});

// 静态文件
app.use(express.static(path.join(__dirname, 'public')));

// ==================== 房间存储 ====================
// Map<roomId, { hostSocketId, authCode, guests: Map<guestId, { socketId, pubKey, nickname }> }>
const rooms = new Map();

// ==================== Socket 事件 ====================
io.on('connection', (socket) => {
  console.log(`[连接] ${socket.id}`);

  // ---- 发起人：创建房间 ----
  socket.on('host-create', ({ roomId, authCode }) => {
    if (rooms.has(roomId)) {
      socket.emit('error', { message: '房间已存在，请刷新重试' });
      return;
    }

    rooms.set(roomId, {
      hostSocketId: socket.id,
      authCode,
      guests: new Map(),
    });

    socket.join(roomId);
    socket.roomId = roomId;
    socket.isHost = true;

    socket.emit('host-created', { roomId });
    console.log(`[房间创建] ${roomId}  by ${socket.id}`);
  });

  // ---- 访客：加入房间 ----
  socket.on('guest-join', ({ roomId, authCode, guestPubKey, nickname }) => {
    const room = rooms.get(roomId);
    if (!room) {
      socket.emit('error', { message: '该聊天服务不存在或已关闭' });
      return;
    }

    const guestId = socket.id;
    room.guests.set(guestId, {
      socketId: socket.id,
      pubKey: guestPubKey,
      nickname,
      approved: false,
    });

    socket.join(roomId);
    socket.roomId = roomId;
    socket.isHost = false;
    socket.guestId = guestId;

    // 通知发起人：有新访客
    io.to(room.hostSocketId).emit('new-guest', {
      guestId,
      guestPubKey,
      nickname,
      authCode,
    });

    console.log(`[访客接入] ${nickname} (${guestId}) → 房间 ${roomId}`);
  });

  // ---- 发起人：批准访客 ----
  socket.on('host-accept-guest', ({ guestId }) => {
    const room = rooms.get(socket.roomId);
    if (!room || socket.id !== room.hostSocketId) return;

    const guest = room.guests.get(guestId);
    if (!guest) return;

    guest.approved = true;
    io.to(guestId).emit('join-approved', { guestId });
    console.log(`[批准] 访客 ${guestId} 已通过`);
  });

  // ---- 发起人：拒绝访客 ----
  socket.on('host-reject-guest', ({ guestId, reason }) => {
    const room = rooms.get(socket.roomId);
    if (!room || socket.id !== room.hostSocketId) return;

    room.guests.delete(guestId);
    io.to(guestId).emit('join-rejected', { reason: reason || '发起人拒绝了连接' });
  });

  // ---- WebRTC 信令转发（核心：只转发，不解析）----
  socket.on('signal', ({ target, payload }) => {
    // 解析目标：target 可能是 'host'（访客→发起人）或 socketId
    let resolvedTarget = target;
    if (target === 'host' && socket.roomId) {
      const room = rooms.get(socket.roomId);
      if (room) {
        resolvedTarget = room.hostSocketId;
      }
    }
    io.to(resolvedTarget).emit('signal', { from: socket.id, payload });
  });

  // ---- 断开连接 ----
  socket.on('disconnect', () => {
    console.log(`[断开] ${socket.id}`);

    // 发起人断开 → 销毁整个房间
    if (socket.isHost && socket.roomId) {
      const room = rooms.get(socket.roomId);
      if (room) {
        room.guests.forEach((_, guestId) => {
          io.to(guestId).emit('host-left');
        });
        rooms.delete(socket.roomId);
        console.log(`[房间销毁] ${socket.roomId}`);
      }
    }

    // 访客断开 → 通知发起人
    if (!socket.isHost && socket.roomId) {
      const room = rooms.get(socket.roomId);
      if (room) {
        room.guests.delete(socket.guestId || socket.id);
        io.to(room.hostSocketId).emit('guest-left', {
          guestId: socket.guestId || socket.id,
        });
      }
    }
  });

  // ---- 发起人主动关闭服务 ----
  socket.on('host-close-room', () => {
    if (!socket.isHost || !socket.roomId) return;
    const room = rooms.get(socket.roomId);
    if (room) {
      room.guests.forEach((_, guestId) => {
        io.to(guestId).emit('host-left');
      });
      rooms.delete(socket.roomId);
      console.log(`[主动关闭] 房间 ${socket.roomId}`);
    }
  });
});

// ==================== 启动 ====================
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🔒 加密聊天信令服务器已启动 → http://localhost:${PORT}`);
  console.log(`   信令服务器仅转发连接信息，不接触聊天内容`);
});
