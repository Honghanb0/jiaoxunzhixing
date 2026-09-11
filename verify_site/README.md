# verify_site —— 检测能力自测靶场

> 本目录是**刻意构造的漏洞测试靶场**，用于验证平台的检测能力（敏感文件暴露、
> 弱口令、XSS/SQL 注入规则、钓鱼页面识别等）。目录里的"漏洞"全部是**设计使然**，
> 不是真实站点的安全问题。

## 重要说明

- **所有凭据均为虚构**：`id_rsa` 是假私钥（内容为 `MIIBfakefakefake...` 占位符）、
  `.env` 里的 `API_KEY=sk-this-is-a-fake-key-for-testing`、`backup.sql` 与
  `wp-config.php` 中的口令均为演示值，**不对应任何真实系统**。
- 本目录**仅限本地/内网**用于自测与演示，请勿将其部署到公网，
  也不要把它当作真实渗透目标的依据。
- 平台的检测规则若能在本靶场上命中，即说明对应检测路径工作正常；
  这也是「检测效果」评估中正样本的来源之一。

## 目录内容速览

| 文件 | 用途 |
|---|---|
| `id_rsa` / `id_rsa.pub` | 敏感私钥暴露检测（假密钥） |
| `.env` / `wp-config.php` / `backup.sql` | 配置/备份文件泄露检测 |
| `index.html` / `page1.html` / `page2.html` | 页面基线与篡改检测的正常样本 |
| `xss.html` / `leak.html` / `phishing.html` | XSS / 敏感信息 / 钓鱼页检测样本 |
| `.htaccess` / `.htpasswd` | 弱配置与口令文件检测 |
