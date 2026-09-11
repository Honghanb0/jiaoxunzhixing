package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/models"
)

type UserRepository struct {
	store *Neo4jStore
}

func NewUserRepository(store *Neo4jStore) *UserRepository {
	return &UserRepository{store: store}
}

func (r *UserRepository) Create(user *models.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	if user.Role == "" {
		user.Role = models.RoleUser
	}
	if user.RoleLevel == 0 {
		user.RoleLevel = models.GetRoleLevel(user.Role)
	}

	query := `CREATE (u:User {id: $id, username: $username, password_hash: $password_hash, role: $role, role_level: $role_level, email: $email, created_at: datetime($created_at), updated_at: datetime($updated_at)})`
	session := r.store.Session()
	defer session.Close()

	_, err := session.Run(query, map[string]any{
		"id": user.ID, "username": user.Username, "password_hash": user.PasswordHash,
		"role": user.Role, "role_level": user.RoleLevel, "email": user.Email,
		"created_at": now.Format(time.RFC3339), "updated_at": now.Format(time.RFC3339),
	})
	return err
}

func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	query := `MATCH (u:User {username: $username}) RETURN u`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"username": username})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("u"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToUser(node), nil
			}
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (r *UserRepository) GetByID(id string) (*models.User, error) {
	query := `MATCH (u:User {id: $id}) RETURN u`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("u"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToUser(node), nil
			}
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (r *UserRepository) ExistsByUsername(username string) (bool, error) {
	query := `MATCH (u:User {username: $username}) RETURN count(u) AS c`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"username": username})
	if err != nil {
		return false, err
	}
	if result.Next() {
		if c, ok := result.Record().Get("c"); ok {
			return toInt(c) > 0, nil
		}
	}
	return false, nil
}

func (r *UserRepository) Count() (int, error) {
	query := `MATCH (u:User) RETURN count(u) AS c`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, nil)
	if err != nil {
		return 0, err
	}
	if result.Next() {
		if c, ok := result.Record().Get("c"); ok {
			return toInt(c), nil
		}
	}
	return 0, nil
}

func (r *UserRepository) List() ([]*models.User, error) {
	query := `MATCH (u:User) RETURN u ORDER BY u.created_at DESC`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, nil)
	if err != nil {
		return nil, err
	}
	var users []*models.User
	for result.Next() {
		if val, ok := result.Record().Get("u"); ok {
			if node, ok := val.(neo4j.Node); ok {
				users = append(users, r.nodeToUser(node))
			}
		}
	}
	return users, result.Err()
}

func (r *UserRepository) UpdateRole(id, role string) error {
	query := `MATCH (u:User {id: $id}) SET u.role = $role, u.role_level = $role_level, u.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "role": role, "role_level": models.GetRoleLevel(role), "updated_at": time.Now().Format(time.RFC3339),
	})
	return err
}

func (r *UserRepository) UpdateRoleLevel(id string, roleLevel int) error {
	query := `MATCH (u:User {id: $id}) SET u.role_level = $role_level, u.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "role_level": roleLevel, "updated_at": time.Now().Format(time.RFC3339),
	})
	return err
}

func (r *UserRepository) Delete(id string) error {
	query := `MATCH (u:User {id: $id}) DETACH DELETE u`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"id": id})
	return err
}

func (r *UserRepository) Update(user *models.User) error {
	query := `MATCH (u:User {id: $id}) SET u.password_hash = $password_hash, u.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": user.ID, "password_hash": user.PasswordHash, "updated_at": time.Now().Format(time.RFC3339),
	})
	return err
}

func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
	return r.GetByUsername(username)
}

func (r *UserRepository) nodeToUser(node neo4j.Node) *models.User {
	props := node.Props
	roleLevel := getInt(props, "role_level")
	if roleLevel == 0 && getStr(props, "role") == models.RoleAdmin {
		roleLevel = models.RoleLevelAdmin
	}
	return &models.User{
		ID: getStr(props, "id"), Username: getStr(props, "username"),
		PasswordHash: getStr(props, "password_hash"), Role: getStr(props, "role"),
		RoleLevel: roleLevel,
		Email:     getStr(props, "email"),
		CreatedAt: getTimeVal(props, "created_at"), UpdatedAt: getTimeVal(props, "updated_at"),
	}
}
