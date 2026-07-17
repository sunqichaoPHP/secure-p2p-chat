/**
 * 端到端加密点对点聊天 —— 前端核心
 *
 * 安全模型：
 *   1. ECDH（Curve25519）协商共享密钥
 *   2. xsalsa20-poly1305（tweetnacl.secretbox）加密消息
 *   3. 密钥仅存在于浏览器内存，不上传
 *   4. 信令服务器仅转发公钥和 WebRTC 握手信息
 */

// ==================== 工具函数 ====================

function $(id) { return document.getElementById(id); }

function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function randomDigits(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => (b % 10).toString()).join('');
}

function showToast(msg, duration = 2500) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), duration);
}

// ==================== 加密模块 ====================

const Crypto = {
  // 生成 ECDH 密钥对（Curve25519）
  generateKeyPair() {
    const kp = nacl.box.keyPair();
    return {
      publicKey:  nacl.util.encodeBase64(kp.publicKey),
      secretKey:  nacl.util.encodeBase64(kp.secretKey),
    };
  },

  // 计算共享密钥：sharedKey = box.before(对方公钥, 我的私钥)
  deriveSharedKey(theirPubKeyB64, mySecKeyB64) {
    const theirPK = nacl.util.decodeBase64(theirPubKeyB64);
    const mySK    = nacl.util.decodeBase64(mySecKeyB64);
    const shared  = nacl.box.before(theirPK, mySK);
    return nacl.util.encodeBase64(shared);
  },

  // 加密消息：nonce(24) + ciphertext
  encrypt(plaintext, sharedKeyB64) {
    const key     = nacl.util.decodeBase64(sharedKeyB64);
    const nonce   = nacl.randomBytes(nacl.secretbox.nonceLength);
    const msg     = nacl.util.decodeUTF8(plaintext);
    const box     = nacl.secretbox(msg, nonce, key);
    if (!box) throw new Error('加密失败');
    // 返回 nonce + ciphertext 的 base64
    const combined = new Uint8Array(nonce.length + box.length);
    combined.set(nonce);
    combined.set(box, nonce.length);
    return nacl.util.encodeBase64(combined);
  },

  // 解密消息
  decrypt(cipherB64, sharedKeyB64) {
    const key      = nacl.util.decodeBase64(sharedKeyB64);
    const combined = nacl.util.decodeBase64(cipherB64);
    const nonce    = combined.slice(0, nacl.secretbox.nonceLength);
    const box      = combined.slice(nacl.secretbox.nonceLength);
    const msg      = nacl.secretbox.open(box, nonce, key);
    if (!msg) throw new Error('解密失败——密钥不匹配或数据被篡改');
    return nacl.util.encodeUTF8(msg);
  },
};

// ==================== WebRTC 模块 ====================

const RTC_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ],
};

/** 创建 PC（仅连接层，不创建 DataChannel） */
function createPeerConnection(signalingSend) {
  const pc = new RTCPeerConnection(RTC_CONFIG);
  pc.onicecandidate = (e) => {
    if (e.candidate) {
      signalingSend({ type: 'ice-candidate', candidate: e.candidate });
    }
  };
  pc.oniceconnectionstatechange = () => {
    console.log('[ICE] 状态变更:', pc.iceConnectionState);
  };
  return pc;
}

// ==================== 发起人逻辑 ====================

const Host = {
  socket: null,
  keyPair: null,

  // 所有访客
  // Map<guestId, { pc, dc, sharedKey, nickname, pubKey, messages[], connected, unread }>
  guests: new Map(),
  activeGuestId: null,

  roomId: null,
  authCode: null,
  nickname: '我',

  init() {
    this.roomId   = randomHex(16);
    this.authCode = randomDigits(6);
    this.keyPair  = Crypto.generateKeyPair();

    $('toggle-service-btn').addEventListener('click', () => this.toggleService());
    $('copy-link-btn').addEventListener('click', () => this.copyLink());
    $('host-send-btn').addEventListener('click', () => this.sendMessage());
    $('host-msg-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.sendMessage(); }
    });
  },

  toggleService() {
    if (this.socket && this.socket.connected) {
      this.stopService();
    } else {
      this.startService();
    }
  },

  startService() {
    this.socket = io({ reconnection: false });

    this.socket.on('connect', () => {
      this.socket.emit('host-create', { roomId: this.roomId, authCode: this.authCode });
    });

    this.socket.on('host-created', ({ roomId }) => {
      this.roomId = roomId;
      this.updateUI('online');
      this.showShareLink();
      showToast('服务已开启，加密通道就绪');
    });

    this.socket.on('new-guest', ({ guestId, guestPubKey, nickname }) => {
      this.onNewGuest(guestId, guestPubKey, nickname);
    });

    this.socket.on('signal', ({ from, payload }) => {
      this.onSignal(from, payload);
    });

    this.socket.on('guest-left', ({ guestId }) => {
      this.onGuestLeft(guestId);
    });

    this.socket.on('error', ({ message }) => {
      showToast(message);
    });

    this.socket.on('disconnect', () => {
      this.updateUI('offline');
      this.guests.clear();
      this.renderGuestTabs();
      this.showChatPlaceholder();
      showToast('信令服务器连接断开');
    });
  },

  stopService() {
    if (this.socket) {
      this.socket.emit('host-close-room');
    }
    // 关闭所有 peer 连接
    this.guests.forEach((g) => {
      try { g.pc.close(); } catch (_) {}
    });
    this.guests.clear();
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.updateUI('offline');
    this.renderGuestTabs();
    this.showChatPlaceholder();
    showToast('服务已关闭，所有链接失效');
  },

  updateUI(state) {
    const badge = $('host-status');
    const btn   = $('toggle-service-btn');
    if (state === 'online') {
      badge.textContent = '运行中';
      badge.className   = 'status-badge online';
      btn.textContent   = '关闭服务';
      btn.className     = 'btn-primary danger';
      $('host-main').classList.remove('hidden');
    } else {
      badge.textContent = '未开启';
      badge.className   = 'status-badge offline';
      btn.textContent   = '开启服务';
      btn.className     = 'btn-primary';
      $('share-section').classList.add('hidden');
      $('host-main').classList.add('hidden');
    }
  },

  showShareLink() {
    // 构造分享链接：哈希部分不会被发送到服务器
    const base  = window.location.origin + window.location.pathname;
    const hash  = `room=${this.roomId}&auth=${this.authCode}&pk=${encodeURIComponent(this.keyPair.publicKey)}`;
    const link  = `${base}#${hash}`;
    $('share-link-input').value = link;
    $('share-section').classList.remove('hidden');
  },

  copyLink() {
    const input = $('share-link-input');
    input.select();
    document.execCommand('copy');
    // 现代 API 回退
    navigator.clipboard?.writeText(input.value);
    showToast('链接已复制，发送给要聊天的人');
  },

  onNewGuest(guestId, guestPubKey, nickname) {
    if (this.guests.has(guestId)) return;

    // 计算共享密钥
    const sharedKey = Crypto.deriveSharedKey(guestPubKey, this.keyPair.secretKey);

    // 发起人是 answer 方：只创建 PC，不创建 DataChannel
    const pc = createPeerConnection((payload) => {
      this.socket.emit('signal', { target: guestId, payload });
    });

    const guestData = {
      pc, dc: null, sharedKey,
      nickname: nickname || '访客',
      pubKey: guestPubKey,
      messages: [],
      connected: false,
      unread: 0,
      iceBuffer: [], // 缓存在 setRemoteDescription 之前到达的 ICE 候选
    };
    this.guests.set(guestId, guestData);

    // 等待访客的 DataChannel（访客是 offer 方）
    pc.ondatachannel = (e) => {
      const dc = e.channel;
      guestData.dc = dc;

      dc.onopen = () => {
        guestData.connected = true;
        this.renderGuestTabs();
        this.updateEncryptionStatus();
        this.addSystemMessage(guestId, `🔒 加密通道已建立（${guestData.nickname}）`);
      };

      dc.onmessage = (e) => {
        try {
          const plain = Crypto.decrypt(e.data, sharedKey);
          guestData.messages.push({ text: plain, from: 'peer', time: Date.now() });
          if (this.activeGuestId !== guestId) guestData.unread++;
          this.renderMessages(guestId);
          this.renderGuestTabs();
        } catch (err) {
          console.error('解密失败:', err);
          this.addSystemMessage(guestId, '⚠️ 收到无法解密的消息');
        }
      };

      dc.onclose = () => {
        guestData.connected = false;
        this.renderGuestTabs();
        this.updateEncryptionStatus();
      };
    };

    // 自动批准 → 访客收到 join-approved 后会发起 offer
    this.socket.emit('host-accept-guest', { guestId });

    // 自动切换到新访客
    this.activeGuestId = guestId;
    this.renderGuestTabs();
    this.showChatForGuest(guestId);
  },

  onSignal(from, payload) {
    const guest = this.guests.get(from);
    if (!guest) return;

    const { pc } = guest;
    try {
      if (payload.type === 'offer') {
        // 访客发来 offer → 发起人创建 answer
        pc.setRemoteDescription(new RTCSessionDescription(payload.sdp)).then(() => {
          // 处理缓存的 ICE 候选
          guest.iceBuffer.forEach(c => pc.addIceCandidate(new RTCIceCandidate(c)));
          guest.iceBuffer = [];
          return pc.createAnswer();
        }).then(answer => {
          return pc.setLocalDescription(answer);
        }).then(() => {
          this.socket.emit('signal', { target: from, payload: { type: 'answer', sdp: pc.localDescription } });
        });
      } else if (payload.type === 'ice-candidate') {
        const candidate = new RTCIceCandidate(payload.candidate);
        if (pc.remoteDescription && pc.remoteDescription.type) {
          pc.addIceCandidate(candidate);
        } else {
          // 远程描述尚未设置，先缓存
          guest.iceBuffer.push(payload.candidate);
        }
      }
    } catch (err) {
      console.error('信令处理失败:', err);
    }
  },

  onGuestLeft(guestId) {
    const guest = this.guests.get(guestId);
    if (!guest) return;
    try { guest.pc.close(); } catch (_) {}
    this.guests.delete(guestId);

    if (this.activeGuestId === guestId) {
      // 切换到第一个剩余的访客
      const remaining = [...this.guests.keys()];
      this.activeGuestId = remaining[0] || null;
      if (this.activeGuestId) {
        this.showChatForGuest(this.activeGuestId);
      } else {
        this.showChatPlaceholder();
      }
    }
    this.renderGuestTabs();
    this.updateEncryptionStatus();
  },

  sendMessage() {
    const guestId = this.activeGuestId;
    if (!guestId) return;
    const guest = this.guests.get(guestId);
    if (!guest || !guest.connected) return;

    const input   = $('host-msg-input');
    const text    = input.value.trim();
    if (!text) return;

    try {
      const cipher = Crypto.encrypt(text, guest.sharedKey);
      guest.dc.send(cipher);
      guest.messages.push({ text, from: 'self', time: Date.now() });
      this.renderMessages(guestId);
    } catch (err) {
      console.error('加密/发送失败:', err);
      showToast('发送失败，加密通道可能已断开');
    }

    input.value = '';
    input.style.height = 'auto';
  },

  switchGuest(guestId) {
    if (this.activeGuestId === guestId) return;
    this.activeGuestId = guestId;
    const guest = this.guests.get(guestId);
    if (guest) { guest.unread = 0; }
    this.showChatForGuest(guestId);
    this.renderGuestTabs();
  },

  showChatForGuest(guestId) {
    const guest = this.guests.get(guestId);
    if (!guest) return;

    $('host-chat-area').classList.remove('chat-placeholder');
    $('host-input-area').classList.remove('hidden');
    this.renderMessages(guestId);
    this.updateEncryptionStatus();
    $('host-msg-input').focus();
  },

  showChatPlaceholder() {
    $('host-chat-area').innerHTML = `
      <div class="chat-placeholder">
        <div class="placeholder-icon">💬</div>
        <p>等待访客接入…</p>
        <p class="placeholder-sub">分享链接后，访客打开即可建立加密通道</p>
      </div>`;
    $('host-input-area').classList.add('hidden');
    $('host-enc-indicator').querySelector('span:last-child').textContent = '等待加密通道建立…';
    $('host-enc-indicator').classList.remove('secure');
  },

  renderGuestTabs() {
    const container = $('guest-tabs');
    if (this.guests.size === 0) {
      container.innerHTML = '';
      return;
    }

    container.innerHTML = [...this.guests.entries()].map(([id, g]) => {
      const active  = id === this.activeGuestId ? ' active' : '';
      const dot     = g.connected ? '<span class="tab-dot"></span>' : '';
      const badge   = g.unread > 0 ? `<span class="tab-unread">${g.unread}</span>` : '';
      return `<button class="guest-tab${active}" data-guest="${id}">${dot}${g.nickname}${badge}</button>`;
    }).join('');

    // 绑定点击
    container.querySelectorAll('.guest-tab').forEach(btn => {
      btn.addEventListener('click', () => this.switchGuest(btn.dataset.guest));
    });
  },

  renderMessages(guestId) {
    const guest = this.guests.get(guestId);
    if (!guest) return;

    const area = $('host-chat-area');
    area.innerHTML = guest.messages.map(m => {
      if (m.system) {
        return `<div class="msg-system"><span class="sys-content">${escHtml(m.text)}</span></div>`;
      }
      const side    = m.from === 'self' ? 'self' : 'peer';
      const sender  = m.from === 'peer' ? `<div class="msg-sender">${escHtml(guest.nickname)}</div>` : '';
      const time    = new Date(m.time).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
      return `
        <div class="msg-row ${side}">
          ${sender}
          <div class="msg-bubble">${escHtml(m.text)}</div>
          <div class="msg-time">${time}</div>
        </div>`;
    }).join('');

    area.scrollTop = area.scrollHeight;
  },

  addSystemMessage(guestId, text) {
    const guest = this.guests.get(guestId);
    if (!guest) return;
    guest.messages.push({ text, system: true, time: Date.now() });
    if (this.activeGuestId === guestId) {
      this.renderMessages(guestId);
    }
  },

  updateEncryptionStatus() {
    const guest = this.guests.get(this.activeGuestId);
    const ind   = $('host-enc-indicator');
    const icon  = ind.querySelector('.lock-icon');
    const text  = ind.querySelector('span:last-child');

    if (guest && guest.connected) {
      ind.className = 'encryption-indicator secure';
      icon.textContent = '🔒';
      text.textContent = `端到端加密 (ECDH + xsalsa20-poly1305)`;
    } else if (guest) {
      ind.className = 'encryption-indicator';
      icon.textContent = '🔓';
      text.textContent = '正在建立加密通道…';
    } else {
      ind.className = 'encryption-indicator';
      icon.textContent = '🔓';
      text.textContent = '等待加密通道建立…';
    }
  },
};

// ==================== 访客逻辑 ====================

const Guest = {
  socket: null,
  keyPair: null,
  sharedKey: null,
  peerConnection: null,
  dataChannel: null,

  roomId: null,
  authCode: null,
  hostPubKey: null,
  nickname: '',
  connected: false,

  messages: [],

  init(params) {
    this.roomId     = params.room;
    this.authCode   = params.auth;
    this.hostPubKey = params.pk;
    this.keyPair    = Crypto.generateKeyPair();

    // 预先计算共享密钥
    if (this.hostPubKey) {
      this.sharedKey = Crypto.deriveSharedKey(this.hostPubKey, this.keyPair.secretKey);
    }

    $('guest-join-btn').addEventListener('click', () => this.join());
    $('guest-nickname-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); this.join(); }
    });
    $('guest-send-btn').addEventListener('click', () => this.sendMessage());
    $('guest-msg-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.sendMessage(); }
    });
  },

  join() {
    const nameInput = $('guest-nickname-input');
    this.nickname = nameInput.value.trim();
    if (!this.nickname) {
      this.nickname = '访客' + randomDigits(4);
    }

    $('guest-join-panel').classList.add('hidden');
    $('guest-chat-panel').classList.remove('hidden');
    $('guest-status').textContent = '连接中…';
    $('guest-status').className = 'status-badge connecting';

    this.connectSignal();
  },

  connectSignal() {
    this.socket = io({ reconnection: false });

    this.socket.on('connect', () => {
      this.socket.emit('guest-join', {
        roomId: this.roomId,
        authCode: this.authCode,
        guestPubKey: this.keyPair.publicKey,
        nickname: this.nickname,
      });
    });

    this.socket.on('join-approved', ({ guestId }) => {
      this.startWebRTC();
    });

    this.socket.on('join-rejected', ({ reason }) => {
      this.showError(reason);
    });

    this.socket.on('signal', ({ from, payload }) => {
      this.onSignal(payload);
    });

    this.socket.on('host-left', () => {
      this.showError('发起人已关闭聊天服务');
      this.cleanup();
    });

    this.socket.on('error', ({ message }) => {
      this.showError(message);
    });

    this.socket.on('disconnect', () => {
      if (this.connected) {
        this.showError('连接已断开');
        this.cleanup();
      }
    });
  },

  startWebRTC() {
    const pc = createPeerConnection((payload) => {
      this.socket.emit('signal', { target: 'host', payload });
    });

    this.peerConnection = pc;

    // ICE 连接状态监控
    pc.oniceconnectionstatechange = () => {
      console.log('[访客 ICE]', pc.iceConnectionState);
      if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') {
        if (!this.connected) {
          this.showError('无法建立点对点连接（网络限制或防火墙阻断）');
          this.cleanup();
        }
      }
    };

    // 访客是 offer 方 → 创建 DataChannel
    const dc = pc.createDataChannel('chat', { ordered: true });
    this.dataChannel = dc;

    dc.onopen = () => {
      if (this._connTimer) { clearTimeout(this._connTimer); this._connTimer = null; }
      this.connected = true;
      $('guest-status').textContent = '已加密';
      $('guest-status').className = 'status-badge online';
      $('guest-input-area').classList.remove('hidden');
      this.updateEncryptionStatus(true);
      this.addSystemMessage('🔒 端到端加密通道已建立');
      $('guest-msg-input').focus();
    };

    dc.onmessage = (e) => {
      try {
        const plain = Crypto.decrypt(e.data, this.sharedKey);
        this.messages.push({ text: plain, from: 'peer', time: Date.now() });
        this.renderMessages();
      } catch (err) {
        console.error('解密失败:', err);
        this.addSystemMessage('⚠️ 收到无法解密的消息');
      }
    };

    dc.onclose = () => {
      this.connected = false;
      this.updateEncryptionStatus(false);
    };

    // 15 秒连接超时
    this._connTimer = setTimeout(() => {
      if (!this.connected) {
        this.showError('连接超时——请确认发起人服务仍在运行，或检查网络设置');
        this.cleanup();
      }
    }, 15000);

    // 创建并发送 offer
    pc.createOffer()
      .then(offer => pc.setLocalDescription(offer))
      .then(() => {
        this.socket.emit('signal', { target: 'host', payload: { type: 'offer', sdp: pc.localDescription } });
      })
      .catch(err => {
        console.error('创建 offer 失败:', err);
        this.showError('创建加密通道失败，请刷新重试');
      });
  },

  onSignal(payload) {
    const pc = this.peerConnection;
    if (!pc) return;
    try {
      if (payload.type === 'answer') {
        pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
      } else if (payload.type === 'ice-candidate') {
        pc.addIceCandidate(new RTCIceCandidate(payload.candidate));
      }
    } catch (err) {
      console.error('信令处理失败:', err);
    }
  },

  sendMessage() {
    if (!this.connected || !this.dataChannel) return;

    const input = $('guest-msg-input');
    const text  = input.value.trim();
    if (!text) return;

    try {
      const cipher = Crypto.encrypt(text, this.sharedKey);
      this.dataChannel.send(cipher);
      this.messages.push({ text, from: 'self', time: Date.now() });
      this.renderMessages();
    } catch (err) {
      console.error('加密/发送失败:', err);
      showToast('发送失败，加密通道可能已断开');
    }

    input.value = '';
    input.style.height = 'auto';
  },

  renderMessages() {
    const area = $('guest-chat-area');
    const hostName = '发起人'; // 访客视角，对方就是发起人
    area.innerHTML = this.messages.map(m => {
      if (m.system) {
        return `<div class="msg-system"><span class="sys-content">${escHtml(m.text)}</span></div>`;
      }
      const side   = m.from === 'self' ? 'self' : 'peer';
      const sender = m.from === 'peer' ? `<div class="msg-sender">${escHtml(hostName)}</div>` : '';
      const time   = new Date(m.time).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
      return `
        <div class="msg-row ${side}">
          ${sender}
          <div class="msg-bubble">${escHtml(m.text)}</div>
          <div class="msg-time">${time}</div>
        </div>`;
    }).join('');
    area.scrollTop = area.scrollHeight;
  },

  addSystemMessage(text) {
    this.messages.push({ text, system: true, time: Date.now() });
    this.renderMessages();
  },

  updateEncryptionStatus(secure) {
    const ind  = $('guest-enc-indicator');
    const icon = ind.querySelector('.lock-icon');
    const text = ind.querySelector('span:last-child');
    if (secure) {
      ind.className = 'encryption-indicator secure';
      icon.textContent = '🔒';
      text.textContent = '端到端加密 (ECDH + xsalsa20-poly1305)';
    } else {
      ind.className = 'encryption-indicator';
      icon.textContent = '🔓';
      text.textContent = '加密通道未建立';
    }
  },

  showError(msg) {
    $('guest-join-panel').classList.add('hidden');
    $('guest-chat-panel').classList.add('hidden');
    $('guest-error-panel').classList.remove('hidden');
    $('guest-error-msg').textContent = msg;
    $('guest-status').textContent = '已断开';
    $('guest-status').className = 'status-badge offline';
  },

  cleanup() {
    if (this._connTimer) { clearTimeout(this._connTimer); this._connTimer = null; }
    if (this.dataChannel) { try { this.dataChannel.close(); } catch (_) {} }
    if (this.peerConnection) { try { this.peerConnection.close(); } catch (_) {} }
    if (this.socket) { try { this.socket.disconnect(); } catch (_) {} }
    this.connected = false;
    this.peerConnection = null;
    this.dataChannel = null;
    this.socket = null;
  },
};

// ==================== HTML 转义 ====================

function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ==================== 入口：判断角色 ====================

function parseHash() {
  const raw = window.location.hash.slice(1); // 去掉 #
  if (!raw) return null;
  const params = {};
  raw.split('&').forEach(pair => {
    const [k, v] = pair.split('=');
    if (k && v !== undefined) params[k] = decodeURIComponent(v);
  });
  return params;
}

(function main() {
  const params = parseHash();

  if (params && params.room && params.pk) {
    // ---- 访客模式 ----
    $('guest-view').classList.remove('hidden');
    $('guest-nickname-input').focus();
    Guest.init(params);
  } else {
    // ---- 发起人模式 ----
    $('host-view').classList.remove('hidden');
    Host.init();
  }
})();
