# 本地启动指南 (Windows)

## 前提条件

### 1. 安装 Go
1. 访问 https://go.dev/dl/ 下载 Windows installer
2. 运行安装程序，默认安装到 `C:\Program Files\Go`
3. 打开命令提示符，验证安装：
   ```
   go version
   ```

### 2. 已有 Neo4j
- 确保 Neo4j 服务正在运行
- 默认端口: 7474 (HTTP), 7687 (Bolt)

## 配置步骤

### 1. 配置 Neo4j 密码
如果还没设置 Neo4j 密码：
```bash
# 访问 http://localhost:7474
# 首次登录用户: neo4j
# 设置新密码，例如: security123
```

### 2. 修改配置文件
编辑 `config.yaml`，修改 Neo4j 连接信息：

```yaml
database:
  neo4j:
    uri: "bolt://localhost:7687"
    username: "neo4j"
    password: "你设置的密码"  # 例如: security123
    database: "neo4j"
```

### 3. 设置环境变量 (可选，AI功能)
```powershell
$env:DEEPSEEK_API_KEY = "你的DeepSeek API Key"
```

获取 DeepSeek API Key: https://platform.deepseek.com/

## 启动项目

### 1. 下载依赖
```powershell
cd e:\coding\shengsaizuoping
go mod download
```

### 2. 启动服务
```powershell
go run ./cmd/server
```

### 3. 访问
- Web界面: http://localhost:8080/web/
- API: http://localhost:8080/api/
- Neo4j Browser: http://localhost:7474

## 快速验证

```powershell
# 测试API健康检查
curl http://localhost:8080/health

# 添加测试域名
curl -X POST http://localhost:8080/api/domains -H "Content-Type: application/json" -d "{\"name\":\"example.com\",\"max_depth\":2,\"max_pages\":50}"
```

## 常见问题

### Neo4j 连接失败
- 确保 Neo4j 服务已启动
- 检查 bolt 端口 7687 是否可用
- 确认用户名密码正确

### Go 命令找不到
- 重启命令提示符
- 或手动添加到 PATH

### 编译错误
```powershell
go mod tidy
go build ./...
```
