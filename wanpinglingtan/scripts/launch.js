'use strict';

/**
 * 启动脚本：以「真实 Electron 模式」运行应用。
 *
 * 某些自动化/沙箱环境会默认注入 ELECTRON_RUN_AS_NODE=1，
 * 该变量会让 electron 二进制退化为普通 Node，导致 require('electron')
 * 拿不到 app / BrowserWindow 等 API。此脚本在启动前清理该变量，
 * 并确保 Chromium 使用可写的临时目录与用户数据目录（避免 GPU/缓存因权限失败）。
 *
 * 用法：npm run launch   (或 node scripts/launch.js)
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const appDir = __dirname.replace(/[\\/]scripts$/, '');
const electronBin = path.join(appDir, 'node_modules', 'electron', 'dist', 'electron.exe');

if (!fs.existsSync(electronBin)) {
  console.error('未找到 electron 可执行文件，请先执行 npm install。');
  process.exit(1);
}

// 清理会让 electron 退化为 Node 的环境变量
delete process.env.ELECTRON_RUN_AS_NODE;

// 为 Chromium 准备可写的临时/用户数据目录（无显示环境常见权限问题）
const writableTmp = path.join(appDir, '.electron-tmp');
fs.mkdirSync(writableTmp, { recursive: true });
process.env.TEMP = writableTmp;
process.env.TMP = writableTmp;
process.env.TMPDIR = writableTmp;

// 无显示/无 GPU 环境：禁用硬件 GPU，改用软件渲染，避免 GPU 进程崩溃导致整进程退出
const safeFlags = [
  '--disable-gpu',
  '--use-gl=swiftshader',
  '--disable-gpu-sandbox',
  '--disable-dev-shm-usage',
  '--no-sandbox',
  '--remote-debugging-port=9222',
  `--user-data-dir=${path.join(writableTmp, 'user-data')}`,
];

const extraArgs = process.argv.slice(2);
const child = spawn(electronBin, [appDir, ...safeFlags, ...extraArgs], {
  cwd: appDir,
  env: process.env,
  stdio: 'inherit',
});

child.on('exit', (code) => process.exit(code === null ? 0 : code));
