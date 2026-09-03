package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"security-agent/internal/config"
	"security-agent/internal/storage"
)

// 本文件为「智能体任务查询」的回归测试。
//
// 背景：taskRepo.Get 曾因 Cypher 末尾 `ORDER BY s.created_at` 引用 OPTIONAL MATCH
// 聚合前的字段，且未调用 res.Err()，导致「无执行步骤的任务」被误判为 task not found、
// GET /api/agent/tasks/:id 返回 404，进而让前端「查看」按钮无反应。
// 这些测试固化该行为，防止复现：
//   - 无步骤任务必须可查（核心回归点）
//   - 有步骤任务按 created_at 升序返回
//   - 不存在的任务返回 "task not found"
//   - Manager.Get 的内存快照路径与 Neo4j 回退路径均正常
//
// 集成测试依赖本地 Neo4j；不可用时通过 t.Skip 自动跳过，不影响无数据库环境的编译/单测。

// repoRoot 从测试文件位置向上查找 go.mod，定位仓库根目录。
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// openTestStore 连接本地 Neo4j（复用仓库 config.yaml 的 database.neo4j 配置）。
// 连接失败则跳过测试，避免无数据库环境下误报失败。
func openTestStore(t *testing.T) *storage.Neo4jStore {
	t.Helper()
	root := repoRoot()
	if root == "" {
		t.Skip("未找到仓库根目录（go.mod），跳过集成测试")
	}
	cfg, err := config.Load(filepath.Join(root, "config.yaml"))
	if err != nil {
		t.Skipf("无法加载 config.yaml，跳过集成测试: %v", err)
	}
	store, err := storage.NewNeo4jStore(&cfg.Database.Neo4j)
	if err != nil {
		t.Skipf("无法连接 Neo4j（%s），跳过集成测试: %v", cfg.Database.Neo4j.URI, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// cleanupTask 删除测试产生的 AgentTask 节点及其步骤，避免污染真实数据库。
func cleanupTask(t *testing.T, store *storage.Neo4jStore, id string) {
	t.Helper()
	sess := store.Session()
	defer sess.Close()
	if _, err := sess.Run("MATCH (t:AgentTask {id:$id}) DETACH DELETE t", map[string]any{"id": id}); err != nil {
		t.Logf("清理测试任务 %s 失败（可忽略）: %v", id, err)
	}
}

// TestTaskRepoGet_NoSteps_Regression 是本次 404 bug 的核心回归点：
// 创建「没有任何执行步骤」的任务，Get 必须成功返回且 steps 为空，绝不能 404。
func TestTaskRepoGet_NoSteps_Regression(t *testing.T) {
	store := openTestStore(t)
	repo := newTaskRepo(store)

	now := time.Now()
	tk := &Task{
		Goal:      "regression-no-steps",
		Status:    TaskStatusCompleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := repo.Create(tk); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	defer cleanupTask(t, store, tk.ID)

	got, err := repo.Get(tk.ID)
	if err != nil {
		// 这正是修复前会触发的故障：无步骤任务被误判为 task not found
		t.Fatalf("无步骤任务 Get 应成功，但返回错误（回归!）: %v", err)
	}
	if got.ID != tk.ID {
		t.Errorf("返回任务 ID 不符: got=%s want=%s", got.ID, tk.ID)
	}
	if got.Status != TaskStatusCompleted {
		t.Errorf("返回任务状态不符: got=%s want=%s", got.Status, TaskStatusCompleted)
	}
	if len(got.Steps) != 0 {
		t.Errorf("无步骤任务应返回 0 个步骤，但得到 %d 个", len(got.Steps))
	}
}

// TestTaskRepoGet_WithSteps_Sorted 验证有步骤任务可被查询，且步骤按 created_at 升序排列。
func TestTaskRepoGet_WithSteps_Sorted(t *testing.T) {
	store := openTestStore(t)
	repo := newTaskRepo(store)

	now := time.Now()
	tk := &Task{
		Goal:      "sorted-steps",
		Status:    TaskStatusCompleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := repo.Create(tk); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	defer cleanupTask(t, store, tk.ID)

	earlier := now.Add(-2 * time.Hour)
	later := now
	// 故意以“乱序”写入：先写 later，再写 earlier
	if err := repo.AppendStep(tk.ID, &Step{Name: "step-later", Status: StepDone, CreatedAt: later, Detail: "b"}); err != nil {
		t.Fatalf("AppendStep(later) 失败: %v", err)
	}
	if err := repo.AppendStep(tk.ID, &Step{Name: "step-earlier", Status: StepDone, CreatedAt: earlier, Detail: "a"}); err != nil {
		t.Fatalf("AppendStep(earlier) 失败: %v", err)
	}

	got, err := repo.Get(tk.ID)
	if err != nil {
		t.Fatalf("有步骤任务 Get 失败: %v", err)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("期望 2 个步骤，但得到 %d 个", len(got.Steps))
	}
	// 升序校验：索引 0 应为更早创建的 step-earlier
	if !got.Steps[0].CreatedAt.Before(got.Steps[1].CreatedAt) {
		t.Errorf("步骤未按 created_at 升序排列: [%v] -> [%v]",
			got.Steps[0].CreatedAt, got.Steps[1].CreatedAt)
	}
	if got.Steps[0].Name != "step-earlier" {
		t.Errorf("升序首步应为 step-earlier，但为 %s", got.Steps[0].Name)
	}
}

// TestTaskRepoGet_NotFound 验证不存在的任务返回明确的 "task not found" 错误。
func TestTaskRepoGet_NotFound(t *testing.T) {
	store := openTestStore(t)
	repo := newTaskRepo(store)

	_, err := repo.Get("no-such-task-" + time.Now().Format("20060102150405"))
	if err == nil {
		t.Fatal("不存在的任务应返回错误，但得到 nil")
	}
	if !strings.Contains(err.Error(), "task not found") {
		t.Errorf("错误应包含 'task not found'，但为: %v", err)
	}
}

// TestManagerGet_MemoryPath 验证 Manager.Get 对运行中（内存）任务直接返回快照，不依赖持久层。
func TestManagerGet_MemoryPath(t *testing.T) {
	now := time.Now()
	m := &Manager{
		tasks: map[string]*Task{
			"mem-x": {
				ID:        "mem-x",
				Goal:      "内存任务",
				Status:    TaskStatusRunning,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		// repo 故意留空：命中内存路径时不应触碰 repo，避免 nil 解引用
	}
	_ = m // 仅用于确保结构体初始化无误

	got, err := m.Get("mem-x")
	if err != nil {
		t.Fatalf("内存任务 Get 应成功: %v", err)
	}
	if got.ID != "mem-x" || got.Status != TaskStatusRunning {
		t.Errorf("内存任务快照字段不符: id=%s status=%s", got.ID, got.Status)
	}
	// 验证返回的是快照副本（修改副本不影响原任务）
	got.Status = TaskStatusFailed
	orig, _ := m.Get("mem-x")
	if orig.Status != TaskStatusRunning {
		t.Errorf("快照应与原任务隔离，但原任务状态被改为 %s", orig.Status)
	}
}

// TestManagerGet_FallbackPath 验证 Manager.Get 在内存未命中时回退到 repo.Get，
// 覆盖此前 404 的真实路径（持久层查询）。
func TestManagerGet_FallbackPath(t *testing.T) {
	store := openTestStore(t)
	repo := newTaskRepo(store)

	m := &Manager{
		repo:  repo,
		tasks: map[string]*Task{}, // 内存为空，强制走 Neo4j 回退
	}

	now := time.Now()
	tk := &Task{
		Goal:      "fallback-task",
		Status:    TaskStatusCompleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := repo.Create(tk); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	defer cleanupTask(t, store, tk.ID)

	got, err := m.Get(tk.ID)
	if err != nil {
		t.Fatalf("回退路径 Get 应成功（回归点）: %v", err)
	}
	if got.ID != tk.ID {
		t.Errorf("回退路径返回任务 ID 不符: got=%s want=%s", got.ID, tk.ID)
	}
}
