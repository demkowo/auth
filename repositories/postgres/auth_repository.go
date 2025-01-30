package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	model "github.com/demkowo/auth/models"
	dbclient "github.com/demkowo/dbclient/client"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

const (
	ADD_ACCOUNT = `
		INSERT INTO public.account (
			id, nickname, email, password, created, updated, blocked, deleted
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
	`
	DELETE_ACCOUNT = `
		UPDATE public.account
		SET deleted = TRUE, updated = $1
		WHERE id = $2;
	`
	EDIT_ACCOUNT = `
		UPDATE public.account
		SET email = $1, blocked = $2, updated = $3
		WHERE id = $4;
	`
	EDIT_ACCOUNT_PASSWORD = `
		UPDATE public.account
		SET password = $1, updated = $2
		WHERE id = $3;
	`
	FIND_ACCOUNTS = `
		SELECT 
			account.id, 
			account.nickname, 
			account.email, 
			account.password,
			ARRAY_AGG(account_roles.name) FILTER (WHERE account_roles.name IS NOT NULL) AS role_names,
			account.created, 
			account.updated, 
			account.blocked, 
			account.deleted
		FROM public.account
		LEFT JOIN public.account_roles ON account_roles.id = account.id
		WHERE account.deleted = FALSE
		GROUP BY 
			account.id, 
			account.nickname, 
			account.email, 
			account.password, 
			account.created, 
			account.updated, 
			account.blocked, 
			account.deleted;
	`
	GET_ACCOUNT_BY_EMAIL = `
		SELECT 
			account.id, 
			account.nickname, 
			account.email, 
			account.password, 
			ARRAY_AGG(account_roles.name) FILTER (WHERE account_roles.name IS NOT NULL) AS role_names,
			account.created, 
			account.updated, 
			account.blocked, 
			account.deleted
		FROM public.account
		LEFT JOIN public.account_roles ON account_roles.id = account.id
		WHERE account.deleted = FALSE AND account.email = $1
		GROUP BY 
			account.id, 
			account.nickname, 
			account.email, 
			account.password, 
			account.created, 
			account.updated, 
			account.blocked, 
			account.deleted;
	`
	GET_ACCOUNT_BY_ID = `
		SELECT 
			account.id,
			account.nickname,
			account.email,
			account.password,
			ARRAY_AGG(account_roles.name) FILTER (WHERE account_roles.name IS NOT NULL) AS role_names,
			ARRAY_AGG(api_keys.key) FILTER (WHERE api_keys.key IS NOT NULL) AS api_keys,
			account.created,
			account.updated,
			account.blocked,
			account.deleted
		FROM public.account
		LEFT JOIN public.account_roles ON account_roles.id = account.id
		LEFT JOIN public.api_keys ON api_keys.account_id = account.id
		WHERE account.deleted = FALSE AND account.id = $1
		GROUP BY 
			account.id, 
			account.nickname, 
			account.email, 
			account.password, 
			account.created, 
			account.updated, 
			account.blocked, 
			account.deleted;
	`

	ADD_APIKEY        = "INSERT INTO public.api_keys (id, key, account_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5);"
	DELETE_APIKEY     = "DELETE FROM public.api_keys WHERE key = $1;"
	GET_APIKEY_BY_Id  = "SELECT id, key, account_id, created_at, expires_at FROM public.api_keys WHERE id = $1;"
	GET_APIKEY_BY_KEY = "SELECT id, key, account_id, created_at, expires_at FROM public.api_keys WHERE key = $1;"

	ADD_ACCOUNT_ROLE         = "INSERT INTO public.account_roles (id, name) VALUES ($1, $2);"
	DELETE_ACCOUNT_ROLE      = "DELETE FROM public.account_roles WHERE id = $1 AND name = $2;"
	FIND_ROLES_BY_ACCOUNT_Id = "SELECT name FROM public.account_roles WHERE id = $1;"
)

type Account interface {
	Add(*model.Account) error
	Delete(uuid.UUID) error
	Find() ([]*model.Account, error)
	GetByEmail(string) (*model.Account, error)
	GetById(uuid.UUID) (*model.Account, error)
	Update(*model.Account) error
	UpdatePassword(uuid.UUID, string) error

	AddAPIKey(*model.APIKey) error
	DeleteAPIKey(string) error
	GetAPIKeyById(uuid.UUID) (*model.APIKey, error)
	GetAPIKeyByKey(string) (*model.APIKey, error)

	AddAccountRole(uuid.UUID, string) error
	DeleteAccountRole(uuid.UUID, string) error
	FindRolesByAccount(uuid.UUID) ([]model.AccountRoles, error)
}

type account struct {
	db dbclient.DbClient
}

func NewAccount(db dbclient.DbClient) Account {
	return &account{
		db: db,
	}
}

func (r *account) Add(acc *model.Account) error {
	now := time.Now()
	acc.Created = now
	acc.Updated = now

	var blocked interface{}
	if acc.Blocked.IsZero() {
		blocked = nil
	} else {
		blocked = acc.Blocked
	}

	_, err := r.db.Exec(ADD_ACCOUNT,
		acc.Id,
		acc.Nickname,
		acc.Email,
		acc.Password,
		acc.Created,
		acc.Updated,
		blocked,
		acc.Deleted,
	)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" {
				log.Printf("duplicate key error on ADD_ACCOUNT: %v", pqErr.Detail)
				return errors.New("account with the given nickname already exists")
			}
		}
		log.Printf("failed to execute db.Exec ADD_ACCOUNT: %v", err)
		return errors.New("failed to create account")
	}

	return nil
}

func (r *account) Delete(accountId uuid.UUID) error {
	_, err := r.db.Exec(DELETE_ACCOUNT, time.Now(), accountId)
	if err != nil {
		log.Printf("failed to execute db.Exec DELETE_ACCOUNT: %v", err)
		return errors.New("failed to delete account")
	}
	return nil
}

func (r *account) Find() ([]*model.Account, error) {
	rows, err := r.db.Query(FIND_ACCOUNTS)
	if err != nil {
		log.Printf("failed to execute db.Query FIND_ACCOUNTS: %v", err)
		return nil, errors.New("failed to find accounts")
	}
	defer rows.Close()

	var accounts []*model.Account
	for rows.Next() {
		var acc model.Account
		var blocked sql.NullTime
		var roleNames pq.StringArray

		if scanErr := rows.Scan(
			&acc.Id,
			&acc.Nickname,
			&acc.Email,
			&acc.Password,
			&roleNames,
			&acc.Created,
			&acc.Updated,
			&blocked,
			&acc.Deleted,
		); scanErr != nil {
			log.Printf("failed to scan rows FIND_ACCOUNTS: %v", scanErr)
			return nil, errors.New("failed to find accounts")
		}

		if blocked.Valid {
			acc.Blocked = blocked.Time
		} else {
			acc.Blocked = time.Time{}
		}

		acc.Roles = make([]model.AccountRoles, len(roleNames))
		for i, roleName := range roleNames {
			acc.Roles[i] = model.AccountRoles{
				Id:   acc.Id,
				Name: roleName,
			}
		}

		accounts = append(accounts, &acc)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		log.Printf("error iterating over accounts: %v", rowsErr)
		return nil, errors.New("failed to find accounts")
	}

	return accounts, nil
}

func (r *account) GetByEmail(email string) (*model.Account, error) {
	row := r.db.QueryRow(GET_ACCOUNT_BY_EMAIL, email)
	var acc model.Account
	var blocked sql.NullTime
	var roleNames pq.StringArray

	err := row.Scan(
		&acc.Id,
		&acc.Nickname,
		&acc.Email,
		&acc.Password,
		&roleNames,
		&acc.Created,
		&acc.Updated,
		&blocked,
		&acc.Deleted,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("account with email %s not found", email)
			return nil, fmt.Errorf("account with email %s not found", email)
		}
		log.Printf("failed to scan rows GET_ACCOUNT_BY_EMAIL: %v", err)
		return nil, errors.New("failed to get account")
	}

	if blocked.Valid {
		acc.Blocked = blocked.Time
	} else {
		acc.Blocked = time.Time{}
	}

	acc.Roles = make([]model.AccountRoles, len(roleNames))
	for i, roleName := range roleNames {
		acc.Roles[i] = model.AccountRoles{
			Id:   acc.Id,
			Name: roleName,
		}
	}

	return &acc, nil
}

func (r *account) GetById(id uuid.UUID) (*model.Account, error) {
	row := r.db.QueryRow(GET_ACCOUNT_BY_ID, id)
	var acc model.Account
	var blocked sql.NullTime
	var roleNames pq.StringArray
	var apiKeys pq.StringArray

	err := row.Scan(
		&acc.Id,
		&acc.Nickname,
		&acc.Email,
		&acc.Password,
		&roleNames,
		&apiKeys,
		&acc.Created,
		&acc.Updated,
		&blocked,
		&acc.Deleted,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("account with id %s not found", id)
			return nil, errors.New("account not found")
		}
		log.Printf("failed to scan rows GET_ACCOUNT_BY_ID: %v", err)
		return nil, errors.New("failed to get account")
	}

	if blocked.Valid {
		acc.Blocked = blocked.Time
	} else {
		acc.Blocked = time.Time{}
	}

	acc.Roles = make([]model.AccountRoles, len(roleNames))
	for i, roleName := range roleNames {
		acc.Roles[i] = model.AccountRoles{
			Id:   acc.Id,
			Name: roleName,
		}
	}

	acc.APIKeys = make([]model.APIKey, len(apiKeys))
	for i, keyVal := range apiKeys {
		acc.APIKeys[i] = model.APIKey{
			AccountId: acc.Id,
			Key:       keyVal,
		}
	}

	return &acc, nil
}

func (r *account) Update(acc *model.Account) error {
	acc.Updated = time.Now()

	var blocked interface{}
	if acc.Blocked.IsZero() {
		blocked = nil
	} else {
		blocked = acc.Blocked
	}

	_, err := r.db.Exec(
		EDIT_ACCOUNT,
		acc.Email,
		blocked,
		acc.Updated,
		acc.Id,
	)
	if err != nil {
		log.Printf("failed to execute db.Exec EDIT_ACCOUNT: %v", err)
		return errors.New("failed to update account")
	}

	return nil
}

func (r *account) UpdatePassword(accountId uuid.UUID, newPassword string) error {
	_, err := r.db.Exec(
		EDIT_ACCOUNT_PASSWORD,
		newPassword,
		time.Now(),
		accountId,
	)
	if err != nil {
		log.Printf("failed to execute db.Exec EDIT_ACCOUNT_PASSWORD: %v", err)
		return errors.New("failed to change password")
	}

	return nil
}

func (r *account) AddAPIKey(apiKey *model.APIKey) error {
	var expiresAt interface{}
	if apiKey.ExpiresAt.IsZero() {
		expiresAt = nil
	} else {
		expiresAt = apiKey.ExpiresAt
	}

	_, err := r.db.Exec(
		ADD_APIKEY,
		apiKey.Id,
		apiKey.Key,
		apiKey.AccountId,
		apiKey.CreatedAt,
		expiresAt,
	)
	if err != nil {
		log.Printf("failed to execute db.Exec ADD_APIKEY: %v", err)
		return errors.New("failed to create API key")
	}

	return nil
}

func (r *account) DeleteAPIKey(key string) error {
	_, err := r.db.Exec(DELETE_APIKEY, key)
	if err != nil {
		log.Printf("failed to execute db.Exec DELETE_APIKEY: %v", err)
		return errors.New("failed to delete API key")
	}

	return nil
}

func (r *account) GetAPIKeyById(id uuid.UUID) (*model.APIKey, error) {
	row := r.db.QueryRow(GET_APIKEY_BY_Id, id)
	var apiKey model.APIKey
	var expiresAt sql.NullTime

	err := row.Scan(
		&apiKey.Id,
		&apiKey.Key,
		&apiKey.AccountId,
		&apiKey.CreatedAt,
		&expiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("API key not found")
			return nil, errors.New("API key not found")
		}
		log.Printf("failed to execute row.Scan GET_APIKEY_BY_Id: %v", err)
		return nil, errors.New("failed to get API Key")
	}

	if expiresAt.Valid {
		apiKey.ExpiresAt = expiresAt.Time
	} else {
		apiKey.ExpiresAt = time.Time{}
	}

	return &apiKey, nil
}

func (r *account) GetAPIKeyByKey(key string) (*model.APIKey, error) {
	row := r.db.QueryRow(GET_APIKEY_BY_KEY, key)
	var apiKey model.APIKey
	var expiresAt sql.NullTime

	err := row.Scan(
		&apiKey.Id,
		&apiKey.Key,
		&apiKey.AccountId,
		&apiKey.CreatedAt,
		&expiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("API key not found")
			return nil, errors.New("API key not found")
		}
		log.Printf("failed to execute row.Scan GET_APIKEY_BY_KEY: %v", err)
		return nil, errors.New("failed to get API Key")
	}

	if expiresAt.Valid {
		apiKey.ExpiresAt = expiresAt.Time
	} else {
		apiKey.ExpiresAt = time.Time{}
	}

	return &apiKey, nil
}

func (r *account) AddAccountRole(accountId uuid.UUID, role string) error {
	_, err := r.db.Exec(ADD_ACCOUNT_ROLE, accountId, role)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" {
				log.Printf("duplicate key error on ADD_ACCOUNT: %v", pqErr.Detail)
				return errors.New("this role is already assigned to the account")
			}
		}
		log.Printf("failed to execute ADD_ACCOUNT_ROLE: %v", err)
		return errors.New("failed to add role to account")
	}
	return nil
}

func (r *account) DeleteAccountRole(accountId uuid.UUID, role string) error {
	_, err := r.db.Exec(DELETE_ACCOUNT_ROLE, accountId, role)
	if err != nil {
		log.Printf("failed to execute DELETE_ACCOUNT_ROLE: %v", err)
		return errors.New("failed to delete role from account")
	}
	return nil
}

func (r *account) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRoles, error) {
	rows, err := r.db.Query(FIND_ROLES_BY_ACCOUNT_Id, accountId)
	if err != nil {
		log.Printf("failed to execute db.Query FIND_ROLES_BY_ACCOUNT_Id: %v", err)
		return nil, errors.New("failed to find roles")
	}
	defer rows.Close()

	var roles []model.AccountRoles
	for rows.Next() {
		var role model.AccountRoles
		if scanErr := rows.Scan(&role.Name); scanErr != nil {
			log.Printf("failed to scan rows FIND_ROLES_BY_ACCOUNT_Id: %v", scanErr)
			return nil, errors.New("failed to find roles")
		}
		role.Id = accountId
		roles = append(roles, role)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		log.Printf("error while iterating over roles: %v", rowsErr)
		return nil, errors.New("failed to find roles")
	}

	return roles, nil
}
