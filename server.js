import net from 'net';
import dns from 'dns';
import crypto from 'crypto';

const PORT = process.env.PORT || 8080;
const TCP_DOMAIN = process.env.RAILWAY_TCP_PROXY_DOMAIN || '';
const TCP_PORT = process.env.RAILWAY_TCP_PROXY_PORT || '';

// --- CONFIG ADMIN & USER MANAGEMENT ---
let ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || 'admin',
  password: process.env.ADMIN_PASS || 'admin123'
};

const adminSessions = new Set();
const proxyUsers = new Map([
  // Default user contoh: user / pass
  ['user1', 'pass123']
]);

// Mode Auth: 'NONE' (Semua bisa akses) atau 'AUTH' (Wajib user & password terdaftar)
let PROXY_AUTH_MODE = 'AUTH'; 

let PROXY_SERVER_INFO = {
  domain: TCP_DOMAIN,
  port: TCP_PORT,
  ip: '',
  fullProxy: ''
};

function updateRailwayProxyIP() {
  if (TCP_DOMAIN) {
    dns.lookup(TCP_DOMAIN, (err, address) => {
      if (!err && address) {
        PROXY_SERVER_INFO.ip = address;
        PROXY_SERVER_INFO.fullProxy = `${address}:${TCP_PORT}`;
      } else {
        PROXY_SERVER_INFO.ip = TCP_DOMAIN;
        PROXY_SERVER_INFO.fullProxy = `${TCP_DOMAIN}:${TCP_PORT}`;
      }
    });
  } else {
    PROXY_SERVER_INFO.fullProxy = 'TCP Proxy Not Set';
  }
}
updateRailwayProxyIP();
setInterval(updateRailwayProxyIP, 1000 * 60 * 30);

// State Konfigurasi DNS
let DNS_CONFIG = {
  mode: 'DOH',
  activeName: 'Cloudflare DoH (Official)',
  dohUrl: 'https://cloudflare-dns.com/dns-query',
  udpServer: '1.1.1.1',
  udpPort: 53
};

const PRESETS = {
  'cf-doh': { name: 'Cloudflare DoH (Official)', type: 'DOH', url: 'https://cloudflare-dns.com/dns-query' },
  'google-doh': { name: 'Google DoH', type: 'DOH', url: 'https://dns.google/dns-query' },
  'quad9-doh': { name: 'Quad9 DoH (Security)', type: 'DOH', url: 'https://dns.quad9.net/dns-query' },
  'adguard-doh': { name: 'AdGuard DoH (Adblock)', type: 'DOH', url: 'https://dns.adguard-dns.com/dns-query' },
  'cf-udp': { name: 'Cloudflare UDP (1.1.1.1)', type: 'UDP', host: '1.1.1.1', port: 53 },
  'google-udp': { name: 'Google UDP (8.8.8.8)', type: 'UDP', host: '8.8.8.8', port: 53 }
};

const activeConnections = new Map();
let connectionIdCounter = 0;
let globalTotalBytesIn = 0;
let globalTotalBytesOut = 0;
const dnsCache = new Map();

async function resolveDomain(hostname) {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && (now - cached.time < 1000 * 60 * 10)) {
    return cached.ip;
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return hostname;
  }

  if (DNS_CONFIG.mode === 'DOH') {
    try {
      const url = new URL(DNS_CONFIG.dohUrl);
      url.searchParams.set('name', hostname);
      url.searchParams.set('type', 'A');

      const res = await fetch(url.toString(), {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(1800)
      });
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        const aRecord = data.Answer.find(ans => ans.type === 1);
        if (aRecord && aRecord.data) {
          dnsCache.set(hostname, { ip: aRecord.data, time: now });
          return aRecord.data;
        }
      }
    } catch (_) {}
  }

  if (DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer) {
    try {
      const resolver = new dns.Resolver();
      resolver.setServers([`${DNS_CONFIG.udpServer}:${DNS_CONFIG.udpPort || 53}`]);
      return await new Promise((resolve, reject) => {
        resolver.resolve4(hostname, (err, addresses) => {
          if (!err && addresses && addresses.length > 0) {
            dnsCache.set(hostname, { ip: addresses[0], time: now });
            resolve(addresses[0]);
          } else {
            reject(err);
          }
        });
      });
    } catch (_) {}
  }

  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      const ip = (!err && address) ? address : '104.16.123.96';
      dnsCache.set(hostname, { ip, time: now });
      resolve(ip);
    });
  });
}

function checkHttpAuth(dataStr) {
  if (PROXY_AUTH_MODE === 'NONE') return true;
  const match = dataStr.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
  if (!match) return false;
  try {
    const creds = Buffer.from(match[1], 'base64').toString('utf-8').split(':');
    const u = creds[0];
    const p = creds.slice(1).join(':');
    return proxyUsers.has(u) && proxyUsers.get(u) === p;
  } catch (_) {
    return false;
  }
}

function parseCookie(dataStr) {
  const match = dataStr.match(/Cookie:\s*([^\r\n]+)/i);
  if (!match) return {};
  const list = {};
  match[1].split(';').forEach(cookie => {
    const parts = cookie.split('=');
    list[parts.shift().trim()] = decodeURI(parts.join('='));
  });
  return list;
}

function isAuthenticatedAdmin(dataStr) {
  const cookies = parseCookie(dataStr);
  return cookies.admin_session && adminSessions.has(cookies.admin_session);
}

const server = net.createServer({ 
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, (clientSocket) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);
  clientSocket.setMaxListeners(0);

  const connId = ++connectionIdCounter;
  const rawIp = clientSocket.remoteAddress || 'Unknown';
  const clientIp = rawIp.replace('::ffff:', '');
  const startTime = Date.now();

  const connData = {
    id: connId,
    clientIp,
    type: 'INITIALIZING',
    target: 'pending',
    startTime,
    bytesIn: 0,
    bytesOut: 0
  };

  let isFirstPacket = true;
  let targetSocket = null;
  let socksState = 0; // 0: Init, 1: Auth, 2: Request

  const bridgeSockets = (sockA, sockB) => {
    sockA.on('data', (d) => { 
      connData.bytesIn += d.length;
      globalTotalBytesIn += d.length;
    });
    sockB.on('data', (d) => { 
      connData.bytesOut += d.length;
      globalTotalBytesOut += d.length;
    });

    sockA.pipe(sockB, { end: true });
    sockB.pipe(sockA, { end: true });

    const cleanup = () => {
      activeConnections.delete(connId);
      sockA.destroy();
      sockB.destroy();
    };

    sockA.on('error', cleanup);
    sockB.on('error', cleanup);
    sockA.on('close', cleanup);
    sockB.on('close', cleanup);
  };

  // --- SOCKS5 HANDLER ---
  const handleSocks5 = async (chunk) => {
    // Tahap 1: Greeting Handshake
    if (socksState === 0) {
      const nmethods = chunk[1];
      const methods = chunk.slice(2, 2 + nmethods);

      if (PROXY_AUTH_MODE === 'AUTH') {
        if (!methods.includes(0x02)) { // 0x02 = Username/Password
          clientSocket.write(Buffer.from([0x05, 0xFF])); // No acceptable methods
          return clientSocket.end();
        }
        socksState = 1;
        clientSocket.write(Buffer.from([0x05, 0x02])); // Request User/Pass Auth
      } else {
        socksState = 2;
        clientSocket.write(Buffer.from([0x05, 0x00])); // No Auth Required
      }
      return;
    }

    // Tahap 2: Auth Verification (Sub-negosiasi User/Pass)
    if (socksState === 1) {
      if (chunk[0] !== 0x01) return clientSocket.end(); // Subnegotiation version 1
      const uLen = chunk[1];
      const username = chunk.slice(2, 2 + uLen).toString('utf-8');
      const pLen = chunk[2 + uLen];
      const password = chunk.slice(3 + uLen, 3 + uLen + pLen).toString('utf-8');

      if (proxyUsers.has(username) && proxyUsers.get(username) === password) {
        socksState = 2;
        clientSocket.write(Buffer.from([0x01, 0x00])); // Auth Success
      } else {
        clientSocket.write(Buffer.from([0x01, 0x01])); // Auth Failure
        return clientSocket.end();
      }
      return;
    }

    // Tahap 3: Connect Request
    if (socksState === 2) {
      if (chunk[0] !== 0x05 || chunk[1] !== 0x01) { // 0x01 = CONNECT Command
        clientSocket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); // Command not supported
        return clientSocket.end();
      }

      let targetHost = '';
      let targetPort = 0;
      const atyp = chunk[3];

      if (atyp === 0x01) { // IPv4
        targetHost = `${chunk[4]}.${chunk[5]}.${chunk[6]}.${chunk[7]}`;
        targetPort = chunk.readUInt16BE(8);
      } else if (atyp === 0x03) { // Domain Name
        const dLen = chunk[4];
        targetHost = chunk.slice(5, 5 + dLen).toString('utf-8');
        targetPort = chunk.readUInt16BE(5 + dLen);
      } else {
        clientSocket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); // Address type not supported
        return clientSocket.end();
      }

      connData.type = 'SOCKS5';
      connData.target = `${targetHost}:${targetPort}`;
      activeConnections.set(connId, connData);

      try {
        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          // SOCKS5 Success Response
          clientSocket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10]));
          
          clientSocket.removeAllListeners('data');
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => {
          activeConnections.delete(connId);
          clientSocket.destroy();
        });
      } catch (err) {
        clientSocket.write(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); // Host unreachable
        clientSocket.end();
      }
    }
  };

  clientSocket.on('data', async (chunk) => {
    if (socksState > 0) {
      return handleSocks5(chunk);
    }

    if (isFirstPacket) {
      isFirstPacket = false;

      // 1. SOCKS5 PROTOCOL ENTRY (0x05)
      if (chunk[0] === 0x05) {
        return handleSocks5(chunk);
      }

      const dataStr = chunk.toString('utf-8');

      // 2. DASHBOARD & REST API
      if (dataStr.startsWith('GET /') || dataStr.startsWith('POST /')) {
        const firstLine = dataStr.split('\r\n')[0];
        const path = firstLine.split(' ')[1] || '/';
        const isAuth = isAuthenticatedAdmin(dataStr);

        // API: Login Admin
        if (path === '/api/login' && dataStr.startsWith('POST')) {
          try {
            const bodyStr = dataStr.split('\r\n\r\n')[1] || '{}';
            const body = JSON.parse(bodyStr);
            if (body.username === ADMIN_CREDENTIALS.username && body.password === ADMIN_CREDENTIALS.password) {
              const token = crypto.randomBytes(16).toString('hex');
              adminSessions.add(token);
              const resBody = JSON.stringify({ success: true });
              clientSocket.write(`HTTP/1.1 200 OK\r\nSet-Cookie: admin_session=${token}; Path=/; HttpOnly\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
            } else {
              const resBody = JSON.stringify({ success: false, error: 'Username atau Password Admin salah!' });
              clientSocket.write(`HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
            }
          } catch (_) {}
          clientSocket.end();
          return;
        }

        // API: Logout Admin
        if (path === '/api/logout' && dataStr.startsWith('POST')) {
          const cookies = parseCookie(dataStr);
          if (cookies.admin_session) adminSessions.delete(cookies.admin_session);
          clientSocket.write(`HTTP/1.1 200 OK\r\nSet-Cookie: admin_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
          clientSocket.end();
          return;
        }

        // API: Stats Realtime
        if (path === '/api/stats') {
          const activeList = Array.from(activeConnections.values())
            .filter(c => !c.target.includes('railway.com') && !c.target.includes('up.railway.app'))
            .map(c => ({
              id: c.id,
              clientIp: c.clientIp,
              type: c.type,
              target: c.target,
              uptime: Math.floor((Date.now() - c.startTime) / 1000),
              bytesIn: formatBytes(c.bytesIn),
              bytesOut: formatBytes(c.bytesOut)
            }));

          const uniqueClients = new Set(activeList.map(c => c.clientIp)).size;

          const resBody = JSON.stringify({
            isAuth,
            proxyInfo: PROXY_SERVER_INFO,
            dnsConfig: DNS_CONFIG,
            authMode: PROXY_AUTH_MODE,
            userList: isAuth ? Array.from(proxyUsers.keys()) : [],
            totalActive: uniqueClients,
            globalTotalIn: formatBytes(globalTotalBytesIn),
            globalTotalOut: formatBytes(globalTotalBytesOut),
            connections: activeList
          });

          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ${Buffer.byteLength(resBody)}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // API: Update DNS (Wajib Admin)
        if (path.startsWith('/api/set-dns') && dataStr.startsWith('POST')) {
          if (!isAuth) {
            clientSocket.write(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
            return clientSocket.end();
          }
          try {
            const bodyStr = dataStr.split('\r\n\r\n')[1] || '{}';
            const body = JSON.parse(bodyStr);

            if (body.preset && PRESETS[body.preset]) {
              const p = PRESETS[body.preset];
              DNS_CONFIG.mode = p.type;
              DNS_CONFIG.activeName = p.name;
              if (p.type === 'DOH') DNS_CONFIG.dohUrl = p.url;
              else { DNS_CONFIG.udpServer = p.host; DNS_CONFIG.udpPort = p.port; }
            } else if (body.mode === 'DOH') {
              DNS_CONFIG.mode = 'DOH';
              DNS_CONFIG.activeName = 'Custom DoH Pribadi';
              DNS_CONFIG.dohUrl = body.dohUrl || 'https://cloudflare-dns.com/dns-query';
            } else if (body.mode === 'UDP') {
              DNS_CONFIG.mode = 'UDP';
              DNS_CONFIG.activeName = 'Custom DNS UDP Pribadi';
              DNS_CONFIG.udpServer = body.udpServer || '1.1.1.1';
              DNS_CONFIG.udpPort = parseInt(body.udpPort, 10) || 53;
            }

            dnsCache.clear();
            const resBody = JSON.stringify({ success: true, config: DNS_CONFIG });
            clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } catch (e) {
            const errBody = JSON.stringify({ success: false, error: e.message });
            clientSocket.write(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: ${errBody.length}\r\nConnection: close\r\n\r\n${errBody}`);
          }
          clientSocket.end();
          return;
        }

        // API: Tambah / Hapus User Proxy (Wajib Admin)
        if (path === '/api/manage-users' && dataStr.startsWith('POST')) {
          if (!isAuth) {
            clientSocket.write(`HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
            return clientSocket.end();
          }
          try {
            const body = JSON.parse(dataStr.split('\r\n\r\n')[1] || '{}');
            if (body.action === 'add' && body.username && body.password) {
              proxyUsers.set(body.username.trim(), body.password.trim());
            } else if (body.action === 'delete' && body.username) {
              proxyUsers.delete(body.username);
            } else if (body.action === 'set-mode' && body.mode) {
              PROXY_AUTH_MODE = body.mode;
            }
            const resBody = JSON.stringify({ success: true, users: Array.from(proxyUsers.keys()), mode: PROXY_AUTH_MODE });
            clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } catch (e) {
            clientSocket.write(`HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
          }
          clientSocket.end();
          return;
        }

        // Dashboard Web UI
        if (path === '/' || path === '/index.html') {
          const html = renderDashboardHTML();
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\nConnection: close\r\n\r\n${html}`);
          clientSocket.end();
          return;
        }

        // 3. HTTP SCANNER / PROXY
        if (!checkHttpAuth(dataStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
          connData.type = 'HTTP SCAN';
          connData.target = `${targetHost}:${targetPort}`;
          activeConnections.set(connId, connData);
        }

        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          targetSocket.write(chunk);
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
        return;
      }

      // 4. HTTPS CONNECT PROXY
      if (dataStr.startsWith('CONNECT ')) {
        if (!checkHttpAuth(dataStr)) {
          const authReq = 'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy Auth"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
          clientSocket.write(authReq);
          return clientSocket.end();
        }

        const match = dataStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;

          if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
            connData.type = 'HTTPS TUNNEL';
            connData.target = `${targetHost}:${targetPort}`;
            activeConnections.set(connId, connData);
          }

          const resolvedIp = await resolveDomain(targetHost);
          targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
            targetSocket.setNoDelay(true);
            targetSocket.setKeepAlive(true, 5000);
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            bridgeSockets(clientSocket, targetSocket);
          });

          targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
          return;
        }
      }

      // 5. STREAM VLESS / TROJAN / TLS SNI
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';

      if (!destinationHost.includes('railway.com') && !destinationHost.includes('up.railway.app')) {
        connData.type = sni ? 'VLESS / TROJAN' : 'RAW TCP';
        connData.target = `${destinationHost}:443`;
        activeConnections.set(connId, connData);
      }

      const resolvedIp = await resolveDomain(destinationHost);
      targetSocket = net.connect({ host: resolvedIp, port: 443, noDelay: true }, () => {
        targetSocket.setNoDelay(true);
        targetSocket.setKeepAlive(true, 5000);
        targetSocket.write(chunk);
        bridgeSockets(clientSocket, targetSocket);
      });

      targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
    }
  });

  clientSocket.on('error', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
  clientSocket.on('close', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
});

function parseTlsSni(buffer) {
  try {
    if (buffer[0] !== 0x16) return null;
    let pos = 43;
    if (pos >= buffer.length) return null;
    const sessionIdLen = buffer[pos];
    pos += 1 + sessionIdLen;
    const cipherSuitesLen = buffer.readUInt16BE(pos);
    pos += 2 + cipherSuitesLen;
    const compMethodsLen = buffer[pos];
    pos += 1 + compMethodsLen;
    if (pos >= buffer.length) return null;
    const extensionsLen = buffer.readUInt16BE(pos);
    pos += 2;
    const endExtensions = pos + extensionsLen;
    while (pos + 4 <= endExtensions && pos + 4 <= buffer.length) {
      const extType = buffer.readUInt16BE(pos);
      const extLen = buffer.readUInt16BE(pos + 2);
      pos += 4;
      if (extType === 0) {
        let sniPos = pos + 2;
        if (buffer[sniPos] === 0) {
          const nameLen = buffer.readUInt16BE(sniPos + 1);
          return buffer.toString('utf8', sniPos + 3, sniPos + 3 + nameLen);
        }
      }
      pos += extLen;
    }
  } catch (_) { return null; }
  return null;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Proxy Hub & Admin Control</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #06090e; color: #00ffcc; padding: 14px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0c121e; border: 1px solid #00ffcc; box-shadow: 0 0 20px rgba(0,255,204,0.15); border-radius: 14px; max-width: 520px; width: 100%; padding: 18px; }
    h2 { margin: 0 0 16px 0; color: #38bdf8; text-align: center; font-size: 1.2rem; }
    .proxy-box { background: #030712; border: 1px solid #38bdf8; border-radius: 10px; padding: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .proxy-title { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .proxy-val { font-family: monospace; font-size: 1.05rem; font-weight: bold; color: #39ff14; }
    .btn-copy { background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 8px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; }
    .badge-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 18px; }
    .badge { background: #030712; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 10px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; }
    .badge .val { font-size: 1.3rem; font-weight: bold; margin-top: 5px; font-family: monospace; }
    .section-title { font-size: 0.85rem; font-weight: bold; color: #38bdf8; margin-top: 16px; margin-bottom: 10px; }
    .conn-list { display: flex; flex-direction: column; gap: 8px; max-height: 200px; overflow-y: auto; }
    .conn-item { background: #030712; border: 1px solid #1e293b; border-left: 3px solid #39ff14; border-radius: 8px; padding: 8px 10px; font-size: 0.8rem; }
    .tag { background: #032b17; color: #39ff14; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; }
    select, input { width: 100%; padding: 9px; background: #030712; border: 1px solid #1e293b; border-radius: 6px; color: #fff; margin-top: 6px; font-family: monospace; font-size: 0.82rem; }
    button { width: 100%; padding: 10px; background: #00ffcc; color: #000; font-weight: bold; border: none; border-radius: 6px; margin-top: 10px; cursor: pointer; }
    .btn-del { background: #ef4444; color: #fff; padding: 4px 8px; border-radius: 4px; border: none; cursor: pointer; font-size: 0.7rem; width: auto; margin-top: 0; }
    .user-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    .user-table td { padding: 6px 4px; border-bottom: 1px solid #1e293b; font-size: 0.8rem; }
    .admin-panel { background: #070d17; border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚡ PROXY HUB (HTTP/S + SOCKS5)</h2>
    
    <div class="proxy-box">
      <div>
        <div class="proxy-title">🚀 Multi-Protocol Server</div>
        <div class="proxy-val" id="proxy_full_text">${PROXY_SERVER_INFO.fullProxy || 'Loading...'}</div>
      </div>
      <button class="btn-copy" onclick="navigator.clipboard.writeText('${PROXY_SERVER_INFO.fullProxy}')">📋 SALIN</button>
    </div>

    <div class="badge-grid">
      <div class="badge"><h4>Koneksi Aktif</h4><div class="val" style="color:#39ff14;" id="active_count">0</div></div>
      <div class="badge"><h4>Mode Auth</h4><div class="val" style="color:#38bdf8; font-size:1.1rem;" id="badge_auth_mode">...</div></div>
      <div class="badge"><h4>Total RX</h4><div class="val" style="color:#00ffcc;" id="total_rx">0 B</div></div>
      <div class="badge"><h4>Total TX</h4><div class="val" style="color:#f59e0b;" id="total_tx">0 B</div></div>
    </div>

    <div class="section-title">🟢 LIVE CONNECTIONS</div>
    <div class="conn-list" id="conn_container"></div>

    <div id="admin_login_box" class="admin-panel" style="display:none; margin-top:16px;">
      <div class="section-title" style="margin-top:0;">🔒 LOGIN ADMIN SETUP</div>
      <input type="text" id="admin_user" placeholder="Username Admin">
      <input type="password" id="admin_pass" placeholder="Password Admin">
      <button onclick="loginAdmin()">MASUK ADMIN</button>
    </div>

    <div id="admin_controls" style="display:none;">
      <div class="admin-panel">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="section-title" style="margin:0;">👤 MANAJEMEN USER PROXY</span>
          <button onclick="logoutAdmin()" style="width:auto; padding:4px 8px; background:#475569; color:#fff; font-size:0.7rem; margin:0;">Logout</button>
        </div>
        <div style="margin-top:8px;">
          <label style="font-size:0.75rem; color:#94a3b8;">Auth Enforce:</label>
          <select id="select_auth_mode" onchange="changeAuthMode()">
            <option value="AUTH">Wajib Auth (Private - SOCKS5 & HTTP)</option>
            <option value="NONE">Tanpa Auth (Public Proxy)</option>
          </select>
        </div>
        
        <table class="user-table">
          <tbody id="user_list_body"></tbody>
        </table>

        <div style="display:flex; gap:6px; margin-top:8px;">
          <input type="text" id="new_proxy_user" placeholder="User Baru">
          <input type="text" id="new_proxy_pass" placeholder="Pass Baru">
        </div>
        <button onclick="addUser()">+ TAMBAH USER</button>
      </div>

      <div class="admin-panel" style="margin-top:12px;">
        <div class="section-title" style="margin:0;">⚙️ DNS RESOLVER</div>
        <select id="preset_select">
          <option value="cf-doh">Cloudflare DoH</option>
          <option value="google-doh">Google DoH</option>
          <option value="quad9-doh">Quad9 DoH</option>
          <option value="adguard-doh">AdGuard DoH</option>
          <option value="cf-udp">Cloudflare UDP (1.1.1.1)</option>
        </select>
        <button onclick="saveDns()">💾 SIMPAN DNS</button>
      </div>
    </div>
  </div>

  <script>
    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('active_count').innerText = data.totalActive;
        document.getElementById('total_rx').innerText = data.globalTotalIn;
        document.getElementById('total_tx').innerText = data.globalTotalOut;
        document.getElementById('badge_auth_mode').innerText = data.authMode;

        if (data.isAuth) {
          document.getElementById('admin_login_box').style.display = 'none';
          document.getElementById('admin_controls').style.display = 'block';
          document.getElementById('select_auth_mode').value = data.authMode;
          renderUsers(data.userList);
        } else {
          document.getElementById('admin_login_box').style.display = 'block';
          document.getElementById('admin_controls').style.display = 'none';
        }

        const container = document.getElementById('conn_container');
        if (!data.connections || data.connections.length === 0) {
          container.innerHTML = '<div style="text-align:center;color:#64748b;font-size:0.75rem;padding:10px;">Belum ada koneksi...</div>';
          return;
        }
        container.innerHTML = data.connections.map(c => \`
          <div class="conn-item">
            <div style="display:flex; justify-content:space-between;">
              <b>\${c.clientIp}</b>
              <span class="tag">\${c.type}</span>
            </div>
            <div style="color:#38bdf8; word-break:break-all; font-family:monospace; margin:2px 0;">🎯 \${c.target}</div>
            <div style="color:#94a3b8; font-size:0.7rem;">⏱️ \${c.uptime}s | RX: \${c.bytesIn} | TX: \${c.bytesOut}</div>
          </div>
        \`).join('');
      } catch (e) {}
    }

    function renderUsers(users) {
      const tbody = document.getElementById('user_list_body');
      if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td style="color:#64748b;">Tidak ada user</td></tr>';
        return;
      }
      tbody.innerHTML = users.map(u => \`
        <tr>
          <td>👤 <b>\${u}</b></td>
          <td style="text-align:right;"><button class="btn-del" onclick="deleteUser('\${u}')">Hapus</button></td>
        </tr>
      \`).join('');
    }

    async function loginAdmin() {
      const u = document.getElementById('admin_user').value;
      const p = document.getElementById('admin_pass').value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      if (res.ok) fetchStats();
      else alert('Login Gagal! Periksa username & password.');
    }

    async function logoutAdmin() {
      await fetch('/api/logout', { method: 'POST' });
      fetchStats();
    }

    async function addUser() {
      const u = document.getElementById('new_proxy_user').value;
      const p = document.getElementById('new_proxy_pass').value;
      if (!u || !p) return alert('Isi user dan pass');
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'add', username: u, password: p })
      });
      document.getElementById('new_proxy_user').value = '';
      document.getElementById('new_proxy_pass').value = '';
      fetchStats();
    }

    async function deleteUser(u) {
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', username: u })
      });
      fetchStats();
    }

    async function changeAuthMode() {
      const mode = document.getElementById('select_auth_mode').value;
      await fetch('/api/manage-users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'set-mode', mode })
      });
      fetchStats();
    }

    async function saveDns() {
      const preset = document.getElementById('preset_select').value;
      await fetch('/api/set-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset })
      });
      alert('DNS berhasil disimpan!');
    }

    setInterval(fetchStats, 2000);
    fetchStats();
  </script>
</body>
</html>`;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Multi-Protocol SOCKS5 & HTTP Proxy running on port ${PORT}`);
});
