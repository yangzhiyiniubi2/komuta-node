
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const UUID = '775671b0-8249-4226-98f3-1c03fae120d8';
const PATH = '/c5afd1813d8d4bfd';
const PORT = process.env.PORT || 3000;
const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>OK</h1></body></html>');
  } else {
    res.writeHead(404); res.end('not found');
  }
});

function wsAccept(key) {
  return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
}

function encodeFrame(data) {
  const len = data.length;
  let head;
  if (len < 126) { head = Buffer.from([0x82, len]); }
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x82; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x82; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([head, data]);
}

server.on('upgrade', (req, socket, head) => {
  const url = (req.url || '').split('?')[0];
  if (url !== PATH || !req.headers['sec-websocket-key']) { socket.destroy(); return; }
  const accept = wsAccept(req.headers['sec-websocket-key']);
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);

  let buf = Buffer.alloc(0);
  let frags = [];
  let tcp = null;
  let tcpReady = false;
  let pending = [];
  let vlessHeaderDone = false;
  let respHeaderSent = false;
  let dead = false;

  function cleanup() {
    if (dead) return; dead = true;
    try { if (tcp) tcp.destroy(); } catch (e) {}
    try { socket.destroy(); } catch (e) {}
  }

  function sendFrame(data) {
    if (dead) return;
    try {
      const CH = 16384;
      if (data.length <= CH) { socket.write(encodeFrame(data)); return; }
      for (let i = 0; i < data.length; i += CH) socket.write(encodeFrame(data.subarray(i, i + CH)));
    } catch (e) { cleanup(); }
  }

  function handleMessage(msg) {
    if (dead) return;
    if (!vlessHeaderDone) {
      try {
        let off = 0;
        const ver = msg[off++];
        if (msg.length < 24) { cleanup(); return; }
        const id = msg.subarray(off, off + 16); off += 16;
        if (!id.equals(uuidBytes)) { cleanup(); return; }
        const addonLen = msg[off++];
        off += addonLen;
        const cmd = msg[off++];
        if (cmd !== 1) { cleanup(); return; }
        const port = msg.readUInt16BE(off); off += 2;
        const atype = msg[off++];
        let host;
        if (atype === 1) { host = Array.from(msg.subarray(off, off + 4)).join('.'); off += 4; }
        else if (atype === 2) { const l = msg[off++]; host = msg.subarray(off, off + l).toString('utf8'); off += l; }
        else if (atype === 3) {
          const parts = [];
          for (let i = 0; i < 8; i++) parts.push(msg.readUInt16BE(off + i * 2).toString(16));
          host = parts.join(':'); off += 16;
        } else { cleanup(); return; }
        const rest = msg.subarray(off);
        vlessHeaderDone = true;
        tcp = net.connect(port, host);
        tcp.setNoDelay(true);
        tcp.on('connect', () => {
          tcpReady = true;
          if (rest.length) tcp.write(rest);
          for (const p of pending) tcp.write(p);
          pending = [];
        });
        tcp.on('data', (chunk) => {
          if (!respHeaderSent) {
            respHeaderSent = true;
            sendFrame(Buffer.concat([Buffer.from([ver, 0]), chunk]));
          } else sendFrame(chunk);
        });
        tcp.on('error', cleanup);
        tcp.on('close', cleanup);
      } catch (e) { cleanup(); }
    } else {
      if (tcpReady && tcp) tcp.write(msg); else pending.push(msg);
    }
  }

  socket.on('data', (chunk) => {
    if (dead) return;
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      let maskKey = null;
      if (masked) { if (buf.length < off + 4) return; maskKey = buf.subarray(off, off + 4); off += 4; }
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (masked && maskKey) {
        const un = Buffer.alloc(len);
        for (let i = 0; i < len; i++) un[i] = payload[i] ^ maskKey[i % 4];
        payload = un;
      }
      buf = buf.subarray(off + len);
      if (opcode === 0x8) { cleanup(); return; }
      if (opcode === 0x9) {
        try { socket.write(Buffer.from([0x8a, 0])); } catch (e) {}
        continue;
      }
      if (opcode === 0x2 || opcode === 0x1 || opcode === 0x0) {
        frags.push(payload);
        if (fin) {
          const msg = frags.length === 1 ? frags[0] : Buffer.concat(frags);
          frags = [];
          handleMessage(msg);
        }
      }
    }
  });
  socket.on('error', cleanup);
  socket.on('close', cleanup);
});

server.listen(PORT, '0.0.0.0', () => console.log('listening on ' + PORT));
