const jwt = require('jsonwebtoken');
const JWT_SECRET = 'mot-chuoi-bi-mat-rat-dai-va-kho-doan-123456';
const { createServer } = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const hostname = '127.0.0.1';
const port = 3000;
const dbFilePath = path.join(__dirname, 'database.csv');
const tasksDbFilePath = path.join(__dirname, 'tasks.csv');

// HÀM HỖ TRỢ (HELPER) KIỂM TRA TOKEN
function authenticateUser(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

  const clientToken = authHeader.split(' ')[1];

  try {
    const decodedPayload = jwt.verify(clientToken, JWT_SECRET);

    if (!fs.existsSync(dbFilePath)) return null;

    const lines = fs.readFileSync(dbFilePath, 'utf8').split(/\r?\n/);
    let isUserStillExist = false;

    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) continue;
      const [savedId] = lines[i].split(',');

      if (savedId === decodedPayload.id) {
        isUserStillExist = true;
        break;
      }
    }

    if (!isUserStillExist) return null;

    return {
      id: decodedPayload.id,
      username: decodedPayload.username
    };
  } catch (error) {
    return null;
  }
}

// ==========================================
// KHỞI TẠO SERVER
// ==========================================
const server = createServer(async (req, res) => {
  const reqPath = req.url.split('?')[0];

  const sendJSON = (statusCode, data) => {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(data));
  };

  const getRequestBody = (req) => {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => body += chunk.toString());
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch (error) {
          reject(error);
        }
      });
    });
  };

  // ---------------------------------------------------------
  // NHÓM 1: AUTH (POST /sign-up, POST /login)
  // ---------------------------------------------------------
  if (req.method === 'POST' && (reqPath === '/sign-up' || reqPath === '/login')) {
    try {
      const { username, password } = await getRequestBody(req);

      if (!username || !password) return sendJSON(400, { status: 'Error', message: 'Thiếu username hoặc password' });

      if (reqPath === '/sign-up') {
        if (/[,\r\n]/.test(username) || /[,\r\n]/.test(password)) {
          return sendJSON(400, {
            status: 'Error',
            message: 'Tên đăng nhập và mật khẩu không được chứa dấu phẩy hoặc ký tự xuống dòng'
          });
        }

        const isFileExist = fs.existsSync(dbFilePath);
        let csvDataToAppend = '';

        if (isFileExist) {
          const lines = fs.readFileSync(dbFilePath, 'utf8').split(/\r?\n/);
          for (let i = 1; i < lines.length; i++) {
            if (!lines[i]) continue;
            const columns = lines[i].split(',');
            const savedUser = columns[1];
            if (savedUser === username) {
              return sendJSON(409, { status: 'Error', message: 'Tài khoản trên đã tồn tại' });
            }
          }
        } else {
          csvDataToAppend += 'id,username,password\n';
        }

        const newUserId = crypto.randomUUID();
        csvDataToAppend += `${newUserId},${username},${password}\n`;
        fs.appendFileSync(dbFilePath, csvDataToAppend, 'utf8');

        return sendJSON(201, {
          status: 'OK',
          message: 'Đăng ký thành công!',
          data: { id: newUserId, username: username }
        });
      }

      else if (reqPath === '/login') {
        if (!fs.existsSync(dbFilePath)) return sendJSON(401, { status: 'Error', message: 'Hệ thống chưa có dữ liệu' });
        const lines = fs.readFileSync(dbFilePath, 'utf8').split(/\r?\n/);
        let loggedInUser = null;

        for (let i = 1; i < lines.length; i++) {
          if (!lines[i]) continue;
          const [savedId, savedUser, savedPass] = lines[i].split(',');
          if (savedUser === username && savedPass === password) {
            loggedInUser = { id: savedId, username: savedUser };
            break;
          }
        }

        if (loggedInUser) {
          const accessToken = jwt.sign(
            { id: loggedInUser.id, username: loggedInUser.username },
            JWT_SECRET,
            { expiresIn: '24h' }
          );
          return sendJSON(200, { status: 'OK', message: 'Đăng nhập thành công!', accessToken: accessToken });
        }

        return sendJSON(401, { status: 'Error', message: 'Sai tên đăng nhập hoặc mật khẩu' });
      }
    } catch (error) {
      return sendJSON(400, { status: 'Error', message: 'JSON không hợp lệ' });
    }
  }

  // ---------------------------------------------------------
  // NHÓM 2: USER API (GET /me, DELETE /user)
  // ---------------------------------------------------------
  else if (req.method === 'GET' && reqPath === '/me') {
    const user = authenticateUser(req);
    if (!user) return sendJSON(401, { status: 'Error', message: 'Vui lòng cung cấp Token hợp lệ' });
    return sendJSON(200, { status: 'OK', message: 'Xác thực thành công!', data: { id: user.id, username: user.username } });
  }

  else if (req.method === 'DELETE' && reqPath === '/user') {
    const user = authenticateUser(req);
    if (!user) return sendJSON(401, { status: 'Error', message: 'Vui lòng cung cấp Token hợp lệ để xoá' });

    const lines = fs.readFileSync(dbFilePath, 'utf8').split(/\r?\n/);
    const remainingLines = lines.filter((line, index) => {
      if (index === 0) return true;
      if (!line) return false;
      const [savedId] = line.split(',');
      return savedId !== user.id;
    });
    fs.writeFileSync(dbFilePath, remainingLines.join('\n') + '\n', 'utf8');

    if (fs.existsSync(tasksDbFilePath)) {
      const taskLines = fs.readFileSync(tasksDbFilePath, 'utf8').split(/\r?\n/);
      let remainingTasks = [];

      for (let i = 0; i < taskLines.length; i++) {
        if (i === 0) {
          remainingTasks.push(taskLines[i]);
          continue;
        }

        const line = taskLines[i];
        if (!line) continue;

        const columns = line.split(',');
        const taskAssigneeId = columns[2];
        const taskCreatorId = columns[3];

        if (taskCreatorId === user.id) {
          continue;
        }

        if (taskAssigneeId === user.id) {
          columns[2] = '';
        }

        remainingTasks.push(columns.join(','));
      }

      fs.writeFileSync(tasksDbFilePath, remainingTasks.join('\n') + '\n', 'utf8');
    }

    return sendJSON(200, { status: 'OK', message: `Đã xoá thành công tài khoản ${user.username} và xử lý các task liên quan.` });
  }

  // =========================================================
  // NHÓM 3: QUẢN LÝ TASKS
  // =========================================================

  else if (req.method === 'POST' && reqPath === '/task') {
    const user = authenticateUser(req);
    if (!user) return sendJSON(401, { status: 'Error', message: 'Token không hợp lệ (401)' });

    try {
      const { title } = await getRequestBody(req);

      if (!title) return sendJSON(400, { status: 'Error', message: 'Vui lòng cung cấp title cho task' });

      if (/[,\r\n]/.test(title)) {
        return sendJSON(400, {
          status: 'Error',
          message: 'Title không được chứa dấu phẩy hoặc ký tự xuống dòng'
        });
      }

      const isFileExist = fs.existsSync(tasksDbFilePath);
      let csvDataToAppend = '';

      if (!isFileExist) csvDataToAppend += 'taskId,title,assigneeId,creatorId\n';

      const taskId = crypto.randomUUID();
      csvDataToAppend += `${taskId},${title},,${user.id}\n`;
      fs.appendFileSync(tasksDbFilePath, csvDataToAppend, 'utf8');

      return sendJSON(201, { status: 'OK', message: 'Tạo task thành công', data: { taskId, title } });
    } catch (error) {
      return sendJSON(400, { status: 'Error', message: 'JSON không hợp lệ' });
    }
  }

  else if (req.method === 'GET' && reqPath === '/tasks') {
    const user = authenticateUser(req);
    if (!user) return sendJSON(401, { status: 'Error', message: 'Token không hợp lệ (401)' });

    if (!fs.existsSync(tasksDbFilePath)) return sendJSON(200, { status: 'OK', data: [] });

    const lines = fs.readFileSync(tasksDbFilePath, 'utf8').split(/\r?\n/);
    const tasks = [];

    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) continue;
      const [taskId, title, assigneeId, creatorId] = lines[i].split(',');
      tasks.push({ taskId, title, assigneeId, creatorId });
    }
    return sendJSON(200, { status: 'OK', data: tasks });
  }

  else if (req.method === 'PATCH' && reqPath === '/assign-task') {
    const user = authenticateUser(req);
    if (!user) return sendJSON(401, { status: 'Error', message: 'Token không hợp lệ (401)' });

    try {
      const { taskId, username } = await getRequestBody(req);

      if (!taskId || !username) {
        return sendJSON(400, { status: 'Error', message: 'Thiếu taskId hoặc username' });
      }

      if (!fs.existsSync(dbFilePath) || !fs.existsSync(tasksDbFilePath)) {
        return sendJSON(500, { status: 'Error', message: 'Dữ liệu hệ thống chưa sẵn sàng' });
      }

      const userLines = fs.readFileSync(dbFilePath, 'utf8').split(/\r?\n/);
      let foundAssigneeId = null;

      for (let i = 1; i < userLines.length; i++) {
        if (!userLines[i]) continue;
        const [savedId, savedUser] = userLines[i].split(',');

        if (savedUser === username) {
          foundAssigneeId = savedId;
          break;
        }
      }

      if (!foundAssigneeId) {
        return sendJSON(404, { status: 'Error', message: `Không tìm thấy người dùng có username là: ${username}` });
      }

      const taskLines = fs.readFileSync(tasksDbFilePath, 'utf8').split(/\r?\n/);
      let isFoundTask = false;
      let isAuthorized = true;
      let isAlreadyAssigned = false;

      for (let i = 1; i < taskLines.length; i++) {
        if (!taskLines[i]) continue;
        const columns = taskLines[i].split(',');

        if (columns[0] === taskId) {
          isFoundTask = true;

          const currentAssignee = columns[2];
          const taskCreatorId = columns[3];

          if (taskCreatorId !== user.id) {
            isAuthorized = false;
            break;
          }

          if (currentAssignee && currentAssignee.trim() !== '') {
            isAlreadyAssigned = true;
            break;
          }

          columns[2] = foundAssigneeId;
          taskLines[i] = columns.join(',');
          break;
        }
      }

      if (!isFoundTask) {
        return sendJSON(404, { status: 'Error', message: 'Không tìm thấy taskId này' });
      }

      if (!isAuthorized) {
        return sendJSON(403, { status: 'Error', message: 'Forbidden: Bạn không có quyền gán task do người khác tạo (403)' });
      }

      if (isAlreadyAssigned) {
        return sendJSON(409, { status: 'Error', message: 'Conflict: Task này đã được gán cho một người khác (409)' });
      }

      fs.writeFileSync(tasksDbFilePath, taskLines.join('\n'), 'utf8');
      return sendJSON(200, { status: 'OK', message: `Đã gán task thành công cho ${username}` });

    } catch (error) {
      return sendJSON(400, { status: 'Error', message: 'JSON không hợp lệ' });
    }
  }

  else if (req.method === 'DELETE' && reqPath === '/task') {
    const user = authenticateUser(req);
    if (!user) return sendJSON(401, { status: 'Error', message: 'Token không hợp lệ (401)' });

    try {
      const { taskId } = await getRequestBody(req);

      if (!taskId) return sendJSON(400, { status: 'Error', message: 'Vui lòng cung cấp taskId để xoá' });
      if (!fs.existsSync(tasksDbFilePath)) return sendJSON(404, { status: 'Error', message: 'Chưa có dữ liệu task' });

      const lines = fs.readFileSync(tasksDbFilePath, 'utf8').split(/\r?\n/);
      let isFound = false;
      let isAuthorized = true;

      const remainingLines = lines.filter((line, index) => {
        if (index === 0) return true;
        if (!line) return false;

        const columns = line.split(',');
        if (columns[0] === taskId) {
          isFound = true;
          const taskCreatorId = columns[3];

          if (taskCreatorId !== user.id) {
            isAuthorized = false;
            return true;
          }
          return false;
        }
        return true;
      });

      if (!isFound) return sendJSON(404, { status: 'Error', message: 'Không tìm thấy taskId này' });
      if (!isAuthorized) return sendJSON(403, { status: 'Error', message: 'Forbidden: Bạn không có quyền xoá task do người khác tạo (403)' });

      fs.writeFileSync(tasksDbFilePath, remainingLines.join('\n') + '\n', 'utf8');
      return sendJSON(200, { status: 'OK', message: 'Đã xoá task thành công' });

    } catch (error) {
      return sendJSON(400, { status: 'Error', message: 'JSON không hợp lệ' });
    }
  }

  // ---------------------------------------------------------
  // NHÓM 4: KHÔNG TÌM THẤY API (404)
  // ---------------------------------------------------------
  else {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Not Found');
  }
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
