package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"security-agent/internal/ai"
	"security-agent/internal/api"
	"security-agent/internal/config"
	"security-agent/internal/logutil"
	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// seedDefaultAdmin 在系统无用户时创建默认管理员。
// 账号/密码可通过环境变量 AUTH_DEFAULT_ADMIN_USERNAME / AUTH_DEFAULT_ADMIN_PASSWORD 覆盖。
// 设置环境变量 RESET_ADMIN_PASSWORD=1 可强制重置admin密码。
func seedDefaultAdmin(store *storage.Neo4jStore, cfg *config.Config) {
	userRepo := storage.NewUserRepository(store)
	count, err := userRepo.Count()
	if err != nil {
		log.Printf("[Auth] 检查用户数量失败（已忽略 seeding）: %v", err)
		return
	}

	username := os.Getenv("AUTH_DEFAULT_ADMIN_USERNAME")
	if username == "" {
		username = "admin"
	}
	password := os.Getenv("AUTH_DEFAULT_ADMIN_PASSWORD")
	if password == "" {
		password = "Admin@123"
	}

	resetPassword := os.Getenv("RESET_ADMIN_PASSWORD") == "1"

	// 如果admin已存在，检查是否需要重置密码
	if count > 0 && !resetPassword {
		log.Printf("[Auth] 已存在 %d 个用户，跳过默认管理员创建", count)
		return
	}

	if resetPassword {
		// 重置admin密码
		admin, err := userRepo.FindByUsername(username)
		if err == nil && admin != nil {
			hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			admin.PasswordHash = string(hash)
			if err := userRepo.Update(admin); err == nil {
				log.Printf("[Auth] 已强制重置管理员 %s 的密码为默认值 Admin@123", username)
			}
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[Auth] 默认管理员密码加密失败（已忽略）: %v", err)
		return
	}

	admin := &models.User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         models.RoleAdmin,
	}
	if err := userRepo.Create(admin); err != nil {
		log.Printf("[Auth] 创建默认管理员失败（已忽略）: %v", err)
		return
	}
	log.Printf("[Auth] 已创建默认管理员账号: %s (密码: Admin@123，请尽快修改)", username)
}

func main() {
	// 支持 -config 指定配置文件，方便多环境部署与隔离验证
	configPath := flag.String("config", "", "配置文件路径（默认依次查找 ./config.yaml、./config/config.yaml）")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 接管标准库 log 输出到环形缓冲（供 /api/logs 拉取），并保留 stdout + 落盘 logs/server.log。
	// 必须在所有业务日志之前安装，确保启动后的日志均可在“系统日志”页查看。
	logutil.Install("logs")

	store, err := storage.NewNeo4jStore(&cfg.Database.Neo4j)
	if err != nil {
		log.Fatalf("Failed to connect to Neo4j: %v", err)
	}
	defer store.Close()

	// 多模型路由中心与扫描引擎在进程内保持单例：
	// HTTP 层、扫描引擎、定时调度器共用同一份实例（含 HTTP 连接池与运行时切换状态）。
	aiMgr := ai.NewManager(&cfg.AI)
	engine := scanner.NewEngine(cfg, store, aiMgr)

	// 回收上次运行遗留的僵死任务（否则会永远停在 running），并启动超时看门狗
	engine.RecoverStaleJobs()
	engine.StartWatchdog()
	defer engine.Stop()

	// 首次启动：若系统中没有任何用户，则创建默认管理员账号。
	seedDefaultAdmin(store, cfg)

	// 单一调度器实例：必须复用同一份 engine / aiMgr，并先 Start() 再注入 HTTP 层。
	// 此前 Cron 不生效的根因正是 server.go 内部 new 了一个“未启动”的调度器副本，
	// 而 main 启动的是另一个副本——界面保存的配置只写进了未启动的那个，永远不被触发。
	alertSvc := scheduler.NewAlertService(&cfg.Alerts,
		storage.NewVulnerabilityRepository(store),
		storage.NewSensitiveInfoRepository(store),
		storage.NewAlertRepository(store))
	sched := scheduler.NewSchedulerWithInspection(&cfg.Scheduler, store, engine, alertSvc, aiMgr)

	server := api.NewServerWithEngine(cfg, store, engine, aiMgr, sched)

	if err := sched.Start(); err != nil {
		log.Printf("Warning: Failed to start scheduler: %v", err)
	}
	defer sched.Stop()

	go func() {
		log.Printf("Server starting on %s", cfg.GetServerAddr())
		if err := server.Run(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	time.Sleep(2 * time.Second)
	log.Println("Server exited")
}
