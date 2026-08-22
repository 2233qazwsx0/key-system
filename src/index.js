/**
 * Roblox Script Key System - Cloudflare Worker
 * Base64 版本：主脚本通过 Base64 编码返回
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS 处理
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Session',
        },
      });
    }

    try {
      // 公共路由
      if (path === '/loader') return await handleLoader(env);
      if (path === '/api/verify' && request.method === 'POST') {
        return await handleVerify(request, env);
      }
      if (path === '/api/script') return await handleScript(request, env);

      // 用户系统
      if (path === '/api/user/login' && request.method === 'POST') {
        return await handleUserLogin(request, env);
      }
      if (path === '/api/user/register' && request.method === 'POST') {
        return await handleUserRegister(request, env);
      }
      if (path.startsWith('/api/user/') && path.endsWith('/keys') && request.method === 'GET') {
        return await handleUserKeys(request, env);
      }
      if (path.startsWith('/api/user/keys/') && path.endsWith('/reset') && request.method === 'POST') {
        return await handleUserResetHWID(request, env);
      }

      // 管理后台登录
      if (path === '/api/admin/login' && request.method === 'POST') {
        return await handleAdminLogin(request, env);
      }

      // 管理后台其他接口（需要验证 session）
      if (path.startsWith('/api/admin/')) {
        const session = await verifyAdminSession(request, env);
        if (!session) {
          return new Response(JSON.stringify({ error: '未授权' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        if (path === '/api/admin/keys' && request.method === 'POST') {
          return await handleAdminGenerateKeys(request, env);
        }
        if (path === '/api/admin/keys' && request.method === 'GET') {
          return await handleAdminListKeys(env);
        }
        if (path === '/api/admin/keys/assign' && request.method === 'POST') {
          return await handleAdminAssignKey(request, env);
        }
        if (path === '/api/admin/users' && request.method === 'GET') {
          return await handleAdminListUsers(env);
        }
        if (path === '/api/admin/users' && request.method === 'POST') {
          return await handleAdminCreateUser(request, env);
        }
        if (path.startsWith('/api/admin/keys/') && request.method === 'DELETE') {
          const keyId = path.split('/').pop();
          return await handleAdminDeleteKey(keyId, env);
        }
        if (path.startsWith('/api/admin/keys/') && path.endsWith('/revoke') && request.method === 'POST') {
          const keyId = path.split('/')[4];
          return await handleAdminRevokeKey(keyId, env);
        }
      }

      // 静态文件（admin 面板）
      if (path === '/' || path.startsWith('/admin')) {
        return env.ASSETS.fetch(request);
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

// Base64 编解码工具
function base64Encode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

// 卡密验证
async function handleVerify(request, env) {
  const { key, hwid } = await request.json();

  if (!key || !hwid) {
    return new Response(JSON.stringify({ error: '缺少参数' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const result = await env.DB.prepare(
    'SELECT * FROM keys WHERE key = ?'
  ).bind(key).first();

  if (!result) {
    return new Response(JSON.stringify({ error: '无效的卡密' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const now = Date.now();

  // 检查重置冷却（24小时）
  if (result.reset_at && (now - result.reset_at) < 86400000) {
    const remainMs = 86400000 - (now - result.reset_at);
    const remainHours = Math.ceil(remainMs / 3600000);
    return new Response(JSON.stringify({ error: `HWID 重置冷却中，剩余 ${remainHours} 小时` }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (result.status === 'revoked') {
    return new Response(JSON.stringify({ error: '卡密已被撤销' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (result.status === 'exhausted') {
    return new Response(JSON.stringify({ error: '卡密已耗尽（使用3次后自动失效）' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // HWID 首次绑定
  if (!result.hwid) {
    await env.DB.prepare('UPDATE keys SET hwid = ?, used_count = 1 WHERE key = ?')
      .bind(hwid, key).run();
  } else if (result.hwid !== hwid) {
    return new Response(JSON.stringify({ error: '卡密已绑定其他设备' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  } else {
    // 同一设备，增加使用计数
    const newCount = result.used_count + 1;
    const newStatus = newCount >= 3 ? 'exhausted' : 'active';
    await env.DB.prepare('UPDATE keys SET used_count = ?, status = ? WHERE key = ?')
      .bind(newCount, newStatus, key).run();
  }

  const token = generateToken();
  const expiresAt = now + 600000; // 10 分钟有效期

  await env.DB.prepare(
    'INSERT INTO tokens (token, key_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(token, result.id, now, expiresAt).run();

  return new Response(JSON.stringify({ success: true, token }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 获取主脚本（Base64 编码）
async function handleScript(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return new Response(JSON.stringify({ error: '缺少 token' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const tokenResult = await env.DB.prepare(
    'SELECT * FROM tokens WHERE token = ?'
  ).bind(token).first();

  if (!tokenResult) {
    return new Response(JSON.stringify({ error: '无效的 token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (tokenResult.expires_at < Date.now()) {
    await env.DB.prepare('DELETE FROM tokens WHERE id = ?')
      .bind(tokenResult.id).run();
    return new Response(JSON.stringify({ error: 'token 已过期' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 使用后立即删除 token（一次性）
  await env.DB.prepare('DELETE FROM tokens WHERE id = ?')
    .bind(tokenResult.id).run();

  try {
    const script = await env.SCRIPT_BUCKET.get('main.lua');
    
    if (!script) {
      return new Response(JSON.stringify({ error: '脚本不存在' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const scriptContent = await script.text();
    const base64Script = base64Encode(scriptContent);

    return new Response(base64Script, {
      headers: { 'Content-Type': 'text/plain' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: '获取脚本失败' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// 管理后台登录
async function handleAdminLogin(request, env) {
  const { username, password } = await request.json();

  const admin = await env.DB.prepare(
    'SELECT * FROM admins WHERE username = ? AND password_hash = ?'
  ).bind(username, password).first();

  if (!admin) {
    return new Response(JSON.stringify({ error: '账号或密码错误' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const sessionToken = generateToken();
  const expiresAt = Date.now() + 86400000; // 24 小时

  await env.DB.prepare(
    'INSERT INTO admin_tokens (token, admin_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(sessionToken, admin.id, Date.now(), expiresAt).run();

  return new Response(JSON.stringify({ success: true, sessionToken }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 验证管理员 session
async function verifyAdminSession(request, env) {
  const sessionToken = request.headers.get('X-Admin-Session');
  
  if (!sessionToken) return null;

  const session = await env.DB.prepare(
    'SELECT * FROM admin_tokens WHERE token = ? AND expires_at > ?'
  ).bind(sessionToken, Date.now()).first();

  return session;
}

// 生成卡密
async function handleAdminGenerateKeys(request, env) {
  const { count } = await request.json();

  if (!count || count < 1) {
    return new Response(JSON.stringify({ error: '参数错误' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const keys = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const key = generateKey();
    await env.DB.prepare(
      'INSERT INTO keys (key, created_at, status) VALUES (?, ?, ?)'
    ).bind(key, now, 'active').run();
    keys.push(key);
  }

  return new Response(JSON.stringify({ success: true, keys }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 列出所有卡密
async function handleAdminListKeys(env) {
  const result = await env.DB.prepare(
    'SELECT * FROM keys ORDER BY created_at DESC LIMIT 100'
  ).all();

  return new Response(JSON.stringify({ success: true, keys: result.results }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 删除卡密
async function handleAdminDeleteKey(keyId, env) {
  await env.DB.prepare('DELETE FROM keys WHERE id = ?')
    .bind(keyId).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// Loader 脚本（Base64 解码版本）
async function handleLoader(env) {
  const loaderCode = `
local HttpService = game:GetService("HttpService")

-- Base64 解码函数
local function base64_decode(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do
            r = r .. (f % 2^i - f % 2^(i-1) > 0 and '1' or '0')
        end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i,i) == '1' and 2^(8-i) or 0)
        end
        return string.char(c)
    end))
end

local function showKeyInput()
    local player = game.Players.LocalPlayer
    local playerGui = player:WaitForChild("PlayerGui")
    
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "KeySystemGui"
    screenGui.Parent = playerGui
    
    local overlay = Instance.new("Frame")
    overlay.Size = UDim2.new(1, 0, 1, 0)
    overlay.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
    overlay.BackgroundTransparency = 0.4
    overlay.BorderSizePixel = 0
    overlay.Parent = screenGui
    
    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(0, 420, 0, 320)
    frame.Position = UDim2.new(0.5, -210, 0.5, -160)
    frame.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
    frame.BorderSizePixel = 0
    frame.Parent = screenGui
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 16)
    corner.Parent = frame
    
    local shadow = Instance.new("Frame")
    shadow.Size = UDim2.new(1, 20, 1, 20)
    shadow.Position = UDim2.new(0, -10, 0, -10)
    shadow.BackgroundColor3 = Color3.fromRGB(59, 130, 246)
    shadow.BackgroundTransparency = 0.85
    shadow.BorderSizePixel = 0
    shadow.Parent = frame
    local shadowCorner = Instance.new("UICorner")
    shadowCorner.CornerRadius = UDim.new(0, 20)
    shadowCorner.Parent = shadow
    
    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 60)
    title.Position = UDim2.new(0, 0, 0, 20)
    title.BackgroundTransparency = 1
    title.Text = "🔐 WindUI 密钥验证"
    title.TextColor3 = Color3.fromRGB(31, 41, 55)
    title.TextSize = 22
    title.Font = Enum.Font.GothamBold
    title.Parent = frame
    
    local description = Instance.new("TextLabel")
    description.Size = UDim2.new(1, -40, 0, 30)
    description.Position = UDim2.new(0, 20, 0, 80)
    description.BackgroundTransparency = 1
    description.Text = "请输入密钥以解锁脚本"
    description.TextColor3 = Color3.fromRGB(107, 114, 128)
    description.TextSize = 14
    description.Font = Enum.Font.Gotham
    description.Parent = frame
    
    local textBox = Instance.new("TextBox")
    textBox.Size = UDim2.new(1, -40, 0, 48)
    textBox.Position = UDim2.new(0, 20, 0, 120)
    textBox.BackgroundColor3 = Color3.fromRGB(245, 247, 251)
    textBox.TextColor3 = Color3.fromRGB(31, 41, 55)
    textBox.PlaceholderText = "在此输入密钥..."
    textBox.PlaceholderColor3 = Color3.fromRGB(156, 163, 175)
    textBox.TextSize = 16
    textBox.Font = Enum.Font.Gotham
    textBox.BorderSizePixel = 0
    textBox.Parent = frame
    
    local textCorner = Instance.new("UICorner")
    textCorner.CornerRadius = UDim.new(0, 12)
    textCorner.Parent = textBox
    
    local textStroke = Instance.new("UIStroke")
    textStroke.Thickness = 1.5
    textStroke.Color = Color3.fromRGB(219, 234, 254)
    textStroke.Parent = textBox
    
    local statusLabel = Instance.new("TextLabel")
    statusLabel.Size = UDim2.new(1, -40, 0, 30)
    statusLabel.Position = UDim2.new(0, 20, 0, 180)
    statusLabel.BackgroundTransparency = 1
    statusLabel.Text = ""
    statusLabel.TextColor3 = Color3.fromRGB(239, 68, 68)
    statusLabel.TextSize = 13
    statusLabel.Font = Enum.Font.Gotham
    statusLabel.TextWrapped = true
    statusLabel.Parent = frame
    
    local verifyButton = Instance.new("TextButton")
    verifyButton.Size = UDim2.new(1, -40, 0, 48)
    verifyButton.Position = UDim2.new(0, 20, 0, 230)
    verifyButton.BackgroundColor3 = Color3.fromRGB(59, 130, 246)
    verifyButton.Text = "✅ 验证密钥"
    verifyButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    verifyButton.TextSize = 16
    verifyButton.Font = Enum.Font.GothamBold
    verifyButton.BorderSizePixel = 0
    verifyButton.Parent = frame
    
    local buttonCorner = Instance.new("UICorner")
    buttonCorner.CornerRadius = UDim.new(0, 12)
    buttonCorner.Parent = verifyButton
    
    local hwid = game:GetService("RbxAnalyticsService"):GetClientId()
    
    verifyButton.MouseButton1Click:Connect(function()
        local key = textBox.Text:gsub("%s+", "")
        if key == "" then
            statusLabel.Text = "❌ 请输入密钥"
            statusLabel.TextColor3 = Color3.fromRGB(239, 68, 68)
            return
        end
        
        verifyButton.Text = "⏳ 验证中..."
        verifyButton.Active = false
        
        local success, response = pcall(function()
            return game:HttpPostAsync(
                "https://ro-key.cua123.ccwu.cc/api/verify",
                HttpService:JSONEncode({
                    key = key,
                    hwid = hwid
                })
            )
        end)
        
        if success then
            local data = HttpService:JSONDecode(response)
            if data.success then
                statusLabel.Text = "✅ 验证成功！正在加载..."
                statusLabel.TextColor3 = Color3.fromRGB(16, 185, 129)
                
                task.wait(0.5)
                
                local scriptSuccess, scriptResponse = pcall(function()
                    return game:HttpGetAsync("https://ro-key.cua123.ccwu.cc/api/script?token=" .. data.token)
                end)
                
                if scriptSuccess then
                    local decodeSuccess, decodedScript = pcall(function()
                        return base64_decode(scriptResponse)
                    end)
                    
                    if decodeSuccess then
                        screenGui:Destroy()
                        loadstring(decodedScript)()
                    else
                        statusLabel.Text = "❌ 脚本解码失败"
                        verifyButton.Text = "✅ 验证密钥"
                        verifyButton.Active = true
                    end
                else
                    statusLabel.Text = "❌ 获取脚本失败"
                    verifyButton.Text = "✅ 验证密钥"
                    verifyButton.Active = true
                end
            else
                statusLabel.Text = "❌ " .. (data.error or "密钥无效")
                verifyButton.Text = "✅ 验证密钥"
                verifyButton.Active = true
            end
        else
            statusLabel.Text = "❌ 连接服务器失败"
            verifyButton.Text = "✅ 验证密钥"
            verifyButton.Active = true
        end
    end)
end

showKeyInput()
`;

  return new Response(loaderCode, {
    headers: { 'Content-Type': 'text/plain' },
  });
}

// 生成随机 token
function generateToken() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 64; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}

// 生成卡密
function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = '';
  for (let i = 0; i < 4; i++) {
    if (i > 0) key += '-';
    for (let j = 0; j < 4; j++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
  }
  return key;
}

// ==================== 用户系统 ====================

// 用户注册
async function handleUserRegister(request, env) {
  const { username } = await request.json();

  if (!username || username.trim().length < 2) {
    return new Response(JSON.stringify({ error: '用户名至少2个字符' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE username = ?'
  ).bind(username.trim()).first();

  if (existing) {
    return new Response(JSON.stringify({ error: '用户名已存在' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const now = Date.now();
  const result = await env.DB.prepare(
    'INSERT INTO users (username, created_at) VALUES (?, ?) RETURNING id'
  ).bind(username.trim(), now).run();

  return new Response(JSON.stringify({ success: true, userId: result.results[0]?.id }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 用户登录（简单，无密码，仅用户名）
async function handleUserLogin(request, env) {
  const { username } = await request.json();

  if (!username) {
    return new Response(JSON.stringify({ error: '缺少用户名' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE username = ?'
  ).bind(username.trim()).first();

  if (!user) {
    return new Response(JSON.stringify({ error: '用户不存在' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ success: true, userId: user.id, username: user.username }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 获取用户名下的卡密列表
async function handleUserKeys(request, env) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const userId = parts[3]; // /api/user/:userId/keys

  if (!userId) {
    return new Response(JSON.stringify({ error: '缺少用户ID' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const result = await env.DB.prepare(
    'SELECT * FROM keys WHERE owner_id = ? ORDER BY created_at DESC'
  ).bind(parseInt(userId)).all();

  return new Response(JSON.stringify({ success: true, keys: result.results }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 用户重置 HWID
async function handleUserResetHWID(request, env) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const keyId = parts[4]; // /api/user/keys/:keyId/reset

  if (!keyId) {
    return new Response(JSON.stringify({ error: '缺少卡密ID' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const { userId } = await request.json();

  // 验证卡密属于该用户
  const key = await env.DB.prepare(
    'SELECT * FROM keys WHERE id = ? AND owner_id = ?'
  ).bind(parseInt(keyId), parseInt(userId)).first();

  if (!key) {
    return new Response(JSON.stringify({ error: '卡密不存在或不属于该用户' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 检查重置冷却（24小时）
  const now = Date.now();
  if (key.reset_at && (now - key.reset_at) < 86400000) {
    const remainMs = 86400000 - (now - key.reset_at);
    const remainHours = Math.ceil(remainMs / 3600000);
    return new Response(JSON.stringify({ error: `重置冷却中，剩余 ${remainHours} 小时` }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 重置 HWID
  await env.DB.prepare(
    'UPDATE keys SET hwid = NULL, used_count = 0, reset_at = ?, status = ? WHERE id = ?'
  ).bind(now, 'active', parseInt(keyId)).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// ==================== 管理员：卡密分配 ====================

// 分配卡密给用户
async function handleAdminAssignKey(request, env) {
  const { keyId, userId } = await request.json();

  if (!keyId || !userId) {
    return new Response(JSON.stringify({ error: '缺少参数' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 检查用户是否存在
  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE id = ?'
  ).bind(parseInt(userId)).first();

  if (!user) {
    return new Response(JSON.stringify({ error: '用户不存在' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 检查卡密是否存在且未分配
  const key = await env.DB.prepare(
    'SELECT * FROM keys WHERE id = ?'
  ).bind(parseInt(keyId)).first();

  if (!key) {
    return new Response(JSON.stringify({ error: '卡密不存在' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (key.owner_id) {
    return new Response(JSON.stringify({ error: '卡密已分配给其他用户' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 分配
  await env.DB.prepare(
    'UPDATE keys SET owner_id = ? WHERE id = ?'
  ).bind(parseInt(userId), parseInt(keyId)).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 列出所有用户
async function handleAdminListUsers(env) {
  const result = await env.DB.prepare(
    'SELECT u.*, COUNT(k.id) as key_count FROM users u LEFT JOIN keys k ON u.id = k.owner_id GROUP BY u.id ORDER BY u.created_at DESC'
  ).all();

  return new Response(JSON.stringify({ success: true, users: result.results }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// 撤销卡密
async function handleAdminRevokeKey(keyId, env) {
  await env.DB.prepare('UPDATE keys SET status = ? WHERE id = ?')
    .bind('revoked', parseInt(keyId)).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}
