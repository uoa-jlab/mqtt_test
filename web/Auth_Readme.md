WebSocket 使用方式

// 1. 取得 token
const { token } = await fetch('/api/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: 'user', password: 'pass'})
}).then(r => r.json());

// 2. 連線（token 在 auth 物件中傳遞）
const socket = io('http://localhost:5000', { auth: { token } });

// 3. 訂閱設備
socket.emit('subscribe', { dn: 'AABBCCDDEEFF' });

// 4. 接收數據（事件名與 SSE 一致）
socket.on('snapshot', data => console.log('初始快照', data));
socket.on('update',   data => console.log('更新', data));
socket.on('stream_ended', d => console.log('流結束', d));
socket.on('error', e => console.error(e));
輪詢使用方式

# 取 token
curl -X POST /api/token -d '{"username":"u","password":"p"}' -H "Content-Type: application/json"

# 輪詢
curl /api/latest/AABBCCDDEEFF -H "Authorization: Bearer <token>"