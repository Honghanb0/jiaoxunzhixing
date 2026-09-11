package api

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"security-agent/internal/agent"
	"security-agent/internal/ai"
	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// NewServer 构建 HTTP 服务（内部创建扫描引擎、模型路由中心、调度器与自主智能体）。
func NewServer(cfg *config.Config, store *storage.Neo4jStore) *Server {
	aiMgr := ai.NewManager(&cfg.AI)
	engine := scanner.NewEngine(cfg, store, aiMgr)
	alertSvc := scheduler.NewAlertService(&cfg.Alerts,
		storage.NewVulnerabilityRepository(store),
		storage.NewSensitiveInfoRepository(store),
		storage.NewAlertRepository(store))
	sched := scheduler.NewSchedulerWithInspection(&cfg.Scheduler, store, engine, alertSvc, aiMgr)
	agentMgr := agent.NewManager(&cfg.Agent, aiMgr, store, engine, sched)
	return NewServerWithEngine(cfg, store, engine, aiMgr, sched, agentMgr)
}

// NewServerWithEngine 使用外部创建好的扫描引擎、模型路由中心、调度器与自主智能体构建服务。
// 调度器/智能体实例由调用方(main)统一创建并 Start()，再注入此处——确保 HTTP 层与
// main 共用同一个“已启动”的实例，否则界面保存的 Cron 只会注册到未启动的副本上。
func NewServerWithEngine(cfg *config.Config, store *storage.Neo4jStore, engine *scanner.Engine, aiMgr *ai.Manager, sched *scheduler.Scheduler, agentMgr *agent.Manager) *Server {
	gin.SetMode(cfg.Server.Mode)

	router := gin.New()
	router.Use(gin.Recovery())

	// 可信代理：默认不信任任何代理，ClientIP() 直接取 TCP 连接来源，
	// 防止攻击者用伪造的 X-Forwarded-For 绕过登录限速、污染审计日志。
	// 只有明确部署在 nginx / LB 之后，才在 config.yaml 的 server.trusted_proxies 里声明代理地址。
	if len(cfg.Server.TrustedProxies) == 0 {
		if err := router.SetTrustedProxies(nil); err != nil {
			log.Printf("[Server] 设置可信代理为空失败（已忽略）: %v", err)
		}
	} else if err := router.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
		log.Printf("[Server] trusted_proxies 配置无效（将退回不信任任何代理）: %v", err)
		_ = router.SetTrustedProxies(nil)
	}

	router.Use(corsMiddleware(cfg.Server.CORSAllowedOrigins))

	domainRepo := storage.NewDomainRepository(store)
	scanJobRepo := storage.NewScanJobRepository(store)
	alertRepo := storage.NewAlertRepository(store)
	userRepo := storage.NewUserRepository(store)
	ticketRepo := storage.NewTicketRepository(store)
	vulnRepo := storage.NewVulnerabilityRepository(store)
	ruleRepo := storage.NewInspectionRuleRepository(store)
	recordRepo := storage.NewInspectionRecordRepository(store)

	// 多模型路由中心：HTTP 层与扫描引擎共用同一实例
	if aiMgr == nil {
		aiMgr = ai.NewManager(&cfg.AI)
	}
	if engine == nil {
		engine = scanner.NewEngine(cfg, store, aiMgr)
	}
	if sched == nil {
		alertSvc := scheduler.NewAlertService(&cfg.Alerts, vulnRepo,
			storage.NewSensitiveInfoRepository(store), alertRepo)
		sched = scheduler.NewSchedulerWithInspection(&cfg.Scheduler, store, engine, alertSvc, aiMgr)
	}

	domainHandler := NewDomainHandler(domainRepo, scanJobRepo, sched)
	scanHandler := NewScanHandler(engine, sched)
	alertHandler := NewAlertHandler(alertRepo)
	authHandler := NewAuthHandler(userRepo, &cfg.Auth)
	ticketHandler := NewTicketHandler(ticketRepo, vulnRepo)
	statsHandler := NewStatsHandler()
	scheduleHandler := NewScheduleHandler()
	aiHandler := NewAIHandler(aiMgr)
	inspHandler := NewInspectionHandler(ruleRepo, recordRepo, domainRepo, sched, aiMgr)
	logHandler := NewLogHandler()
	assetHandler := NewAssetHandler(engine)
	retestHandler := NewRetestHandler(engine, vulnRepo)
	// engine 为 nil 时基线能力不可用（例如仅构造 HTTP 层做单测），此时不注册相关路由。
	var baselineHandler *BaselineHandler
	if engine != nil {
		baselineHandler = NewBaselineHandler(engine, storage.NewBaselineRepository(store), scanJobRepo, domainRepo)
	}

	// 自主智能体（多轮工具调用 + 自主规划）：若调用方未注入则按需构建
	if agentMgr == nil && aiMgr != nil && engine != nil && sched != nil {
		agentMgr = agent.NewManager(&cfg.Agent, aiMgr, store, engine, sched)
	}
	agentHandler := NewAgentHandler(agentMgr)

	// 公开认证接口（无需登录）
	pub := router.Group("/api/auth")
	{
		pub.POST("/register", authHandler.Register)
		pub.POST("/login", authHandler.Login)
	}

	// 受保护接口：所有 /api 下的业务接口均需有效 JWT
	protected := router.Group("/api")
	protected.Use(AuthMiddleware(cfg.Auth.JwtSecret))
	{
		// 认证相关（需登录）
		protected.POST("/auth/logout", authHandler.Logout)
		protected.GET("/auth/me", authHandler.Me)

		domains := protected.Group("/domains")
		{
			domains.GET("", domainHandler.List)
			domains.POST("", domainHandler.Create)
			domains.GET("/:id", domainHandler.Get)
			domains.PUT("/:id", domainHandler.Update)
			domains.DELETE("/:id", domainHandler.Delete)
			domains.GET("/:id/scans", domainHandler.GetScanJobs)
		}

		// 巡检基线：设置/删除属于改变巡检判定基准的操作，要求巡检员及以上
		if baselineHandler != nil {
			domains.GET("/:id/baseline", baselineHandler.Get)
			domains.GET("/:id/baseline/diff", baselineHandler.Diff)
			domains.POST("/:id/baseline", RequireRoleLevel(models.RoleLevelScanner), baselineHandler.Set)
			domains.DELETE("/:id/baseline", RequireRoleLevel(models.RoleLevelScanner), baselineHandler.Delete)
		}

		scan := protected.Group("/scan")
		{
			scan.POST("/start", scanHandler.StartScan)
			// 规则列表（必须在 /:id 之前注册，避免路由冲突）
			scan.GET("/rules", scanHandler.ListRules)
			scan.GET("/:id/results", scanHandler.GetScanResults)
			scan.GET("/:id/report", scanHandler.GetReport)
			scan.GET("/:id/status", scanHandler.GetScanStatus)
			scan.GET("/:id/progress", scanHandler.GetScanProgress)
			scan.GET("/:id/logs", scanHandler.GetScanLogs)
		}

		tickets := protected.Group("/tickets")
		{
			tickets.GET("", ticketHandler.List)
			tickets.POST("", ticketHandler.Create)
			// 注意：具体路径必须在 /:id 前面，否则会被 /:id 优先匹配
			tickets.POST("/batch-delete", ticketHandler.DeleteBatch)
			tickets.POST("/merge", ticketHandler.Merge)
			tickets.GET("/:id", ticketHandler.Get)
			tickets.PATCH("/:id", ticketHandler.Update)
			tickets.POST("/:id/notes", ticketHandler.AddNote)
			tickets.DELETE("/:id", ticketHandler.Delete)
		}

		// 风险复测：复测会真实请求目标 URL，属于主动动作，要求巡检员及以上
		vulns := protected.Group("/vulnerabilities")
		{
			vulns.GET("/:id", retestHandler.Get)
			vulns.POST("/:id/retest", RequireRoleLevel(models.RoleLevelScanner), retestHandler.Retest)
		}

		admin := protected.Group("/admin")
		admin.Use(RequireRoleLevel(models.RoleLevelAdmin))
		{
			admin.GET("/users", authHandler.ListUsers)
			admin.PATCH("/users/:id/role", authHandler.UpdateRole)
			admin.PATCH("/users/:id/password", authHandler.ChangePassword)
			admin.DELETE("/users/:id", authHandler.DeleteUser)
			// 切换默认大模型 / 调用策略
			admin.PUT("/ai/default", aiHandler.SetDefault)
		}

		alerts := protected.Group("/alerts")
		{
			alerts.GET("", alertHandler.List)
			alerts.GET("/stats", alertHandler.GetStats)
			alerts.GET("/:id", alertHandler.Get)
			alerts.PATCH("/:id", alertHandler.UpdateStatus)
			alerts.POST("/:id/verify", alertHandler.Verify)
		}

		protected.GET("/stats", statsHandler.Get)

		// 服务端日志（CLI 风格日志页）：审计员(role_level>=2)及以上可见
		logs := protected.Group("/logs")
		logs.GET("", RequireRoleLevel(models.RoleLevelViewAdmin), logHandler.Get)

		schedules := protected.Group("/schedules")
		{
			schedules.POST("/validate", scheduleHandler.Validate)
		}

		// AI 自动巡检：规则管理 + 巡检记录查询
		inspections := protected.Group("/inspections")
		{
			inspections.GET("/rules", inspHandler.ListRules)
			inspections.GET("/rules/:id", inspHandler.GetRule)
			inspections.POST("/rules", RequireRoleLevel(models.RoleLevelScanner), inspHandler.CreateRule)
			inspections.PUT("/rules/:id", RequireRoleLevel(models.RoleLevelScanner), inspHandler.UpdateRule)
			inspections.DELETE("/rules/:id", RequireRoleLevel(models.RoleLevelScanner), inspHandler.DeleteRule)
			inspections.POST("/rules/:id/run", RequireRoleLevel(models.RoleLevelScanner), inspHandler.RunRule)
			inspections.GET("/records", inspHandler.ListRecords)
			inspections.GET("/records/:id", inspHandler.GetRecord)
			inspections.GET("/stats", inspHandler.Stats)
		}

		// 多模型统一接入层（DeepSeek / Kimi / GLM）
		aimodels := protected.Group("/ai")
		{
			aimodels.GET("/providers", aiHandler.ListProviders)
			aimodels.POST("/chat", aiHandler.Chat)
			aimodels.POST("/chat/stream", aiHandler.Stream)
			aimodels.POST("/compare", aiHandler.Compare)
			aimodels.POST("/providers/:name/test", aiHandler.TestProvider)
		}

		// 网络资产：暴露面扫描 + 拓扑结构图
		assets := protected.Group("/assets")
		{
			assets.POST("/scan/:domain_id", assetHandler.ScanAssets)
			assets.GET("/graph/:domain_id", assetHandler.GetAssetGraph)
			assets.GET("/list/:domain_id", assetHandler.ListAssets)
		}

		// 自主智能体：多轮工具调用 + 自主规划（连接平台数据库并执行复杂多步骤任务）
		// 权限：操作员(role_level>=1)及以上，因为智能体会对平台执行扫描/建单等动作。
		agents := protected.Group("/agent")
		agents.Use(RequireRoleLevel(models.RoleLevelScanner))
		{
			agents.POST("/run", agentHandler.Run)
			agents.GET("/tasks", agentHandler.ListTasks)
			agents.GET("/tasks/:id", agentHandler.GetTask)
			agents.POST("/tasks/:id/stop", agentHandler.StopTask)
			agents.GET("/tools", agentHandler.ListTools)
		}
	}

	// 前端静态资源（SPA）。web_root 默认 ./web，并兼容“从其他目录启动二进制”的情况。
	webRoot := resolveWebRoot(cfg.Server.WebRoot)
	router.Static("/web", webRoot)

	// 根路径直接返回前端首页，消除 http://localhost:8080/ 的 404。
	router.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(webRoot, "index.html"))
	})

	// SPA 兜底：未匹配的 GET 请求（非 /api、非 /health）回退到首页，
	// 避免刷新或直链到未知路径时出现 404。
	router.NoRoute(func(c *gin.Context) {
		if c.Request.Method == http.MethodGet &&
			!strings.HasPrefix(c.Request.URL.Path, "/api") &&
			!strings.HasPrefix(c.Request.URL.Path, "/health") {
			c.File(filepath.Join(webRoot, "index.html"))
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not found", "path": c.Request.URL.Path})
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	return &Server{router: router, cfg: cfg}
}

// resolveWebRoot 解析前端根目录：优先使用配置值；若相对路径不存在，
// 则回退到可执行文件所在目录下的 web/，提升“从任意目录启动”的稳定性与一致性。
func resolveWebRoot(configured string) string {
	if strings.TrimSpace(configured) == "" {
		configured = "./web"
	}
	if _, err := os.Stat(configured); err == nil {
		if abs, err := filepath.Abs(configured); err == nil {
			return abs
		}
		return configured
	}
	// 配置路径不存在时，尝试相对于可执行文件
	if exe, err := os.Executable(); err == nil {
		alt := filepath.Join(filepath.Dir(exe), "web")
		if _, err := os.Stat(alt); err == nil {
			return alt
		}
	}
	return configured
}

type Server struct {
	router *gin.Engine
	cfg    *config.Config
}

// Run 启动 HTTP 服务。
//
// 跨平台说明：端口被占用在 Windows（如被残留进程/IIS/Skype 占用）与 Linux
// （如被旧实例或容器占用）上都会发生，而 Gin 默认只输出一句 "listen tcp ...:
// address already in use"。这里先做一次预检，把错误翻译成可操作的中文提示，
// 并给出 Windows 与 Linux 两种排查命令，避免部署时误判为程序崩溃。
func (s *Server) Run() error {
	addr := s.cfg.GetServerAddr()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("无法监听 %s：%w\n"+
			"  可能原因：端口已被其他进程占用，或当前用户无权限绑定该端口（Linux 下 <1024 需 root）。\n"+
			"  排查命令：\n"+
			"    Windows: netstat -ano | findstr :%s  （随后 taskkill /F /PID <pid>）\n"+
			"    Linux  : ss -lntp | grep ':%s'  或 lsof -i :%s  （随后 kill -9 <pid>）\n"+
			"  也可通过配置文件 server.port 改用其它端口。",
			addr, err, portOf(addr), portOf(addr), portOf(addr))
	}
	// 预检通过后关闭探测监听，交给 Gin 正式监听（二者之间窗口极小，仅用于给出友好报错）
	_ = ln.Close()

	return s.router.Run(addr)
}

// portOf 从监听地址中取出端口部分，用于错误信息提示。
func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}

// corsMiddleware 跨域支持（白名单模式）。
//
// 安全修复：此前实现是把请求头里的 Origin 原样回显（任意源都放行），
// 只要将来有人加上 Access-Control-Allow-Credentials，就等于任何网站都能跨域读取后台数据。
// 现在改为白名单：只有 server.cors_allowed_origins 里显式列出的源才回 CORS 头，
// 其余一律不回；由于前端由本服务直接托管（同源），留空即为最安全的默认值。
//
// 关键点：Access-Control-Allow-Headers 必须包含 Authorization，
// 否则前端携带 Bearer Token 的请求会在预检(OPTIONS)阶段被浏览器拦截，
// 表现为 fetch() 直接抛 "Failed to fetch"，根本拿不到响应。
func corsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allow := make(map[string]struct{}, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if o == "*" {
			allowAll = true
			continue
		}
		allow[strings.TrimRight(o, "/")] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := strings.TrimRight(c.Request.Header.Get("Origin"), "/")
		if origin != "" && (allowAll || hasOrigin(allow, origin)) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
			c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
			c.Writer.Header().Set("Access-Control-Max-Age", "86400")
		}

		if c.Request.Method == http.MethodOptions {
			// 未列入白名单的预检请求不回 CORS 头，浏览器据此拒绝后续实际请求
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// hasOrigin 判断 Origin 是否在白名单内（忽略大小写）。
func hasOrigin(allow map[string]struct{}, origin string) bool {
	if _, ok := allow[origin]; ok {
		return true
	}
	if _, ok := allow[strings.ToLower(origin)]; ok {
		return true
	}
	return false
}
