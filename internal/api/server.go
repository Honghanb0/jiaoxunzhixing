package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"security-agent/internal/ai"
	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// NewServer 构建 HTTP 服务（内部创建扫描引擎、模型路由中心与调度器）。
func NewServer(cfg *config.Config, store *storage.Neo4jStore) *Server {
	aiMgr := ai.NewManager(&cfg.AI)
	engine := scanner.NewEngine(cfg, store, aiMgr)
	alertSvc := scheduler.NewAlertService(&cfg.Alerts,
		storage.NewVulnerabilityRepository(store),
		storage.NewSensitiveInfoRepository(store),
		storage.NewAlertRepository(store))
	sched := scheduler.NewSchedulerWithInspection(&cfg.Scheduler, store, engine, alertSvc, aiMgr)
	return NewServerWithEngine(cfg, store, engine, aiMgr, sched)
}

// NewServerWithEngine 使用外部创建好的扫描引擎、模型路由中心与调度器构建服务。
// 调度器实例由调用方(main)统一创建并 Start()，再注入此处——确保 HTTP 层与
// main 共用同一个“已启动”的实例，否则界面保存的 Cron 只会注册到未启动的副本上。
func NewServerWithEngine(cfg *config.Config, store *storage.Neo4jStore, engine *scanner.Engine, aiMgr *ai.Manager, sched *scheduler.Scheduler) *Server {
	gin.SetMode(cfg.Server.Mode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(corsMiddleware())

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

		scan := protected.Group("/scan")
		{
			scan.POST("/start", scanHandler.StartScan)
			scan.GET("/:id/results", scanHandler.GetScanResults)
			scan.GET("/:id/status", scanHandler.GetScanStatus)
			scan.GET("/:id/progress", scanHandler.GetScanProgress)
			scan.GET("/:id/logs", scanHandler.GetScanLogs)
		}

		tickets := protected.Group("/tickets")
		{
			tickets.GET("", ticketHandler.List)
			tickets.POST("", ticketHandler.Create)
			tickets.GET("/:id", ticketHandler.Get)
			tickets.PATCH("/:id", ticketHandler.Update)
			tickets.POST("/:id/notes", ticketHandler.AddNote)
		}

		admin := protected.Group("/admin")
		admin.Use(RequireRoleLevel(models.RoleLevelAdmin))
		{
			admin.GET("/users", authHandler.ListUsers)
			admin.PATCH("/users/:id/role", authHandler.UpdateRole)
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

func (s *Server) Run() error {
	return s.router.Run(s.cfg.GetServerAddr())
}

// corsMiddleware 跨域支持。
// 关键点：Access-Control-Allow-Headers 必须包含 Authorization，
// 否则前端携带 Bearer Token 的请求会在预检(OPTIONS)阶段被浏览器拦截，
// 表现为 fetch() 直接抛 "Failed to fetch"，根本拿不到响应。
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
