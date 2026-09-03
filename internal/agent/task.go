package agent

import (
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/storage"
)

// taskRepo 将任务状态持久化到 Neo4j（:AgentTask 节点 + :AgentStep 子节点），
// 使任务在进程重启后仍可回看，并满足「状态跟踪」的审计需求。
type taskRepo struct {
	store *storage.Neo4jStore
}

func newTaskRepo(store *storage.Neo4jStore) *taskRepo { return &taskRepo{store: store} }

func (r *taskRepo) Create(t *Task) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	t.UpdatedAt = time.Now()
	query := `CREATE (t:AgentTask {id:$id, goal:$goal, status:$status, provider:$provider, model:$model,
		result:$result, error:$error, turns:0, created_at:datetime($created_at), updated_at:datetime($updated_at)})`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": t.ID, "goal": t.Goal, "status": string(t.Status),
		"provider": t.Provider, "model": t.Model, "result": t.Result, "error": t.Error,
		"created_at": t.CreatedAt.Format(time.RFC3339), "updated_at": t.UpdatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *taskRepo) Update(t *Task) error {
	t.UpdatedAt = time.Now()
	query := `MATCH (t:AgentTask {id:$id})
		SET t.status=$status, t.result=$result, t.error=$error, t.turns=$turns, t.model=$model,
		    t.updated_at=datetime($updated_at),
		    t.completed_at=CASE WHEN $completed_at IS NULL THEN NULL ELSE datetime($completed_at) END`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": t.ID, "status": string(t.Status), "result": t.Result, "error": t.Error,
		"turns": t.Turns, "model": t.Model, "updated_at": t.UpdatedAt.Format(time.RFC3339),
		"completed_at": nullableTime(t.CompletedAt),
	})
	return err
}

func (r *taskRepo) AppendStep(taskID string, step *Step) error {
	if step.ID == "" {
		step.ID = uuid.New().String()
	}
	if step.CreatedAt.IsZero() {
		step.CreatedAt = time.Now()
	}
	query := `MATCH (t:AgentTask {id:$tid})
		CREATE (t)-[:HAS_STEP]->(s:AgentStep {id:$id, name:$name, status:$status, detail:$detail, result:$result, created_at:datetime($created_at)})`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"tid": taskID, "id": step.ID, "name": step.Name, "status": string(step.Status),
		"detail": step.Detail, "result": step.Result, "created_at": step.CreatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *taskRepo) UpdateStep(taskID, stepID string, status StepStatus, result string) error {
	query := `MATCH (t:AgentTask {id:$tid})-[:HAS_STEP]->(s:AgentStep {id:$sid})
		SET s.status=$status, s.result=$result`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"tid": taskID, "sid": stepID, "status": string(status), "result": result})
	return err
}

func (r *taskRepo) Get(id string) (*Task, error) {
	session := r.store.Session()
	defer session.Close()
	// 注意：原查询在 RETURN 后使用 `ORDER BY s.created_at` 引用了 OPTIONAL MATCH 出来的
	// 聚合前字段 s，当任务无执行步骤（s 为 null）或 Neo4j 版本校验该 ORDER BY 表达式不在
	// RETURN 列表时，会静默报错并导致 res.Next() 返回 false，最终被上层误判为「task not found」。
	// 这里移除 ORDER BY，改为在 Go 侧按步骤创建时间排序，避免该隐患。
	res, err := session.Run(`MATCH (t:AgentTask {id:$id})
		OPTIONAL MATCH (t)-[:HAS_STEP]->(s:AgentStep)
		RETURN t, collect(s) AS steps`, map[string]any{"id": id})
	if err != nil {
		log.Printf("[Agent][taskRepo.Get] 查询失败 id=%s err=%v", id, err)
		return nil, err
	}
	if res.Next() {
		rec := res.Record()
		tVal, _ := rec.Get("t")
		node, ok := tVal.(neo4j.Node)
		if !ok {
			log.Printf("[Agent][taskRepo.Get] 节点类型断言失败 id=%s 实际类型=%T 值=%v", id, tVal, tVal)
			return nil, fmt.Errorf("task not found")
		}
		task := nodeToTask(node)
		if stepsVal, ok := rec.Get("steps"); ok {
			if list, ok := stepsVal.([]any); ok {
				for _, item := range list {
					if sn, ok := item.(neo4j.Node); ok {
						task.Steps = append(task.Steps, nodeToStep(sn))
					}
				}
			}
		}
		// 按步骤创建时间排序，保证回看顺序稳定
		sort.SliceStable(task.Steps, func(i, j int) bool {
			return task.Steps[i].CreatedAt.Before(task.Steps[j].CreatedAt)
		})
		// 检查遍历过程中的流式错误（原实现未调用 res.Err()，会吞掉真实错误）
		if err := res.Err(); err != nil {
			log.Printf("[Agent][taskRepo.Get] 结果遍历告警 id=%s err=%v", id, err)
		}
		log.Printf("[Agent][taskRepo.Get] 查询成功 id=%s status=%s steps=%d", id, task.Status, len(task.Steps))
		return task, nil
	}
	// 遍历结束仍无记录：区分「无数据」与「遍历出错」
	if err := res.Err(); err != nil {
		log.Printf("[Agent][taskRepo.Get] 结果遍历错误 id=%s err=%v", id, err)
		return nil, err
	}
	log.Printf("[Agent][taskRepo.Get] 未找到任务（无匹配记录） id=%s", id)
	return nil, fmt.Errorf("task not found")
}

func (r *taskRepo) List(limit int) ([]*Task, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	session := r.store.Session()
	defer session.Close()
	res, err := session.Run(`MATCH (t:AgentTask) RETURN t ORDER BY t.created_at DESC LIMIT $limit`, map[string]any{"limit": limit})
	if err != nil {
		return nil, err
	}
	var tasks []*Task
	for res.Next() {
		if v, ok := res.Record().Get("t"); ok {
			if node, ok := v.(neo4j.Node); ok {
				tasks = append(tasks, nodeToTask(node))
			}
		}
	}
	return tasks, res.Err()
}

func nodeToTask(node neo4j.Node) *Task {
	p := node.Props
	t := &Task{
		ID:        getStr(p, "id"),
		Goal:      getStr(p, "goal"),
		Status:    TaskStatus(getStr(p, "status")),
		Provider:  getStr(p, "provider"),
		Model:     getStr(p, "model"),
		Result:    getStr(p, "result"),
		Error:     getStr(p, "error"),
		Turns:     getIntProp(p, "turns"),
		CreatedAt: getTimeProp(p, "created_at"),
		UpdatedAt: getTimeProp(p, "updated_at"),
	}
	if ct := getTimeProp(p, "completed_at"); !ct.IsZero() {
		t.CompletedAt = &ct
	}
	return t
}

func nodeToStep(node neo4j.Node) Step {
	p := node.Props
	return Step{
		ID:        getStr(p, "id"),
		Name:      getStr(p, "name"),
		Status:    StepStatus(getStr(p, "status")),
		Detail:    getStr(p, "detail"),
		Result:    getStr(p, "result"),
		CreatedAt: getTimeProp(p, "created_at"),
	}
}

// ---------- 类型转换辅助（与 storage 包内同名函数保持一致语义）----------

func getStr(p map[string]any, key string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return ""
}

func getIntProp(p map[string]any, key string) int {
	switch v := p[key].(type) {
	case int64:
		return int(v)
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func getTimeProp(p map[string]any, key string) time.Time {
	if v, ok := p[key].(time.Time); ok {
		return v
	}
	return time.Time{}
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}
