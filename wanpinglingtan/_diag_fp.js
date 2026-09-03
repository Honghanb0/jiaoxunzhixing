'use strict';
// 诊断脚本：分析指纹库加载情况 + 过度匹配（问题数量偏多）+ 报错根因
const path = require('path');
const secscanDir = path.join(__dirname, 'src', 'secscan');
const security = require(path.join(secscanDir, 'security'));
const fs = require('fs');

console.log('=== 1) 指纹库加载情况 ===');
const db = security.loadFpDb();
console.log('总指纹条数:', db.fingerprints.length, '| http维度:', db.fpsHttp.length, '| banner维度:', db.fpsBanner.length);

// 单独测试 high_risk 容忍解析是否成功
const hrPath = path.join(secscanDir, 'data', 'high_risk_fingerprint_db.json');
let hrRaw = fs.readFileSync(hrPath, 'utf8');
const before = hrRaw.length;
// 复刻 readFpFile 的 tolerant 替换
const replaced = hrRaw.replace(/'([^']*)'/g, (m, inner) => '"' + inner.replace(/"/g, '\\"') + '"');
let hrOk = true, hrErr = '';
try { JSON.parse(replaced); } catch (e) { hrOk = false; hrErr = e.message; }
console.log('high_risk 原始字节:', before, '| tolerant替换后能解析:', hrOk, hrOk ? '' : ('失败原因: ' + hrErr.slice(0,80)));
// 统计 high_risk 中单引号出现次数（可能造成破坏的关键）
const singleQuotes = (hrRaw.match(/'/g) || []).length;
console.log('high_risk 中单引号数量:', singleQuotes, '(这些都会被替换为双引号，可能破坏字符串内部字面量)');

console.log('\n=== 2) 过度匹配测试：用一段通用页面模拟 ===');
// 模拟一个非常通用的首页（很多站点都会命中“login/管理/API”等通用词）
const generic = {
  server: 'nginx/1.18.0',
  headerLines: 'server: nginx/1.18.0\ncontent-type: text/html',
  body: '<html><head><title>欢迎</title></head><body><form><input type=password>用户登录 login manage api admin console</form><div>powered by some app</div></body></html>',
  cookieStr: 'sessionid=abc',
  title: '欢迎',
  pathHits: [],
  faviconHash: null,
  faviconMd5: null,
};
const hits = security.matchHighRisk(db.fpsHttp, generic);
console.log('通用页面命中指纹数:', hits.length);
// 统计命中维度分布
const dimCount = {};
for (const h of hits) {
  for (const d of h.matched) dimCount[d] = (dimCount[d] || 0) + 1;
}
console.log('命中维度分布:', JSON.stringify(dimCount));
console.log('部分命中示例(前15):');
for (const h of hits.slice(0, 15)) console.log('  -', h.product, '['+h.severity+']', '命中:', h.matched.join(','));

console.log('\n=== 3) 极低信号页面（仅含 admin 一词）===');
const low = { server:'', headerLines:'', body:'<div>admin</div>', cookieStr:'', title:'', pathHits:[], faviconHash:null, faviconMd5:null };
const hits2 = security.matchHighRisk(db.fpsHttp, low);
console.log('仅含 admin 一词的页面命中数:', hits2.length);
const dim2 = {};
for (const h of hits2) for (const d of h.matched) dim2[d]=(dim2[d]||0)+1;
console.log('命中维度分布:', JSON.stringify(dim2));
