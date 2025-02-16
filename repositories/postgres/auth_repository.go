package postgres

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	model "github.com/demkowo/auth/models"
	dbclient "github.com/demkowo/dbclient/client"
	"github.com/demkowo/utils/resp"
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
	DELETE_APIKEY     = "DELETE FROM public.api_keys WHERE id = $1;"
	GET_APIKEY_BY_Id  = "SELECT id, key, account_id, created_at, expires_at FROM public.api_keys WHERE id = $1;"
	GET_APIKEY_BY_KEY = "SELECT id, key, account_id, created_at, expires_at FROM public.api_keys WHERE id = $1;"

	ADD_ACCOUNT_ROLE            = "INSERT INTO public.account_roles (id, name) VALUES ($1, $2);"
	DELETE_ACCOUNT_ROLE_BY_ID   = "DELETE FROM public.account_roles WHERE id = $1;"
	DELETE_ACCOUNT_ROLE_BY_NAME = "DELETE FROM public.account_roles WHERE name = $1;"
	FIND_ROLES_BY_ACCOUNT_Id    = "SELECT name FROM public.account_roles WHERE id = $1;"

	ADD_OAUTH2_TOKEN    = `INSERT INTO public.oauth2_tokens (account_id, access_token, refresh_token, expiry) VALUES ($1, $2, $3, $4)`
	GET_OAUTH2_TOKEN    = `SELECT access_token, refresh_token, expiry FROM public.oauth2_tokens WHERE account_id = $1`
	DELETE_OAUTH2_TOKEN = `DELETE FROM public.oauth2_tokens WHERE account_id = $1`
)

type Account interface {
	CreateTables() error

	Add(*model.Account) (*model.Account, *resp.Err)
	Delete(uuid.UUID) *resp.Err
	Find() ([]*model.Account, *resp.Err)
	GetByEmail(string) (*model.Account, *resp.Err)
	GetById(uuid.UUID) (*model.Account, *resp.Err)
	Update(*model.Account) (*model.Account, *resp.Err)
	UpdatePassword(uuid.UUID, string) *resp.Err

	AddAPIKey(*model.APIKey) (*model.APIKey, *resp.Err)
	DeleteAPIKey(uuid.UUID) *resp.Err
	GetAPIKeyById(uuid.UUID) (*model.APIKey, *resp.Err)
	GetAPIKeyByKey(string) (*model.APIKey, *resp.Err)

	AddAccountRole(uuid.UUID, string) (*model.AccountRole, *resp.Err)
	DeleteAccountRoleById(uuid.UUID) *resp.Err
	DeleteAccountRoleByName(string) *resp.Err
	FindRolesByAccount(uuid.UUID) ([]model.AccountRole, *resp.Err)

	AddOAuth2Token(accountId string, token *model.OAuth2Token) *resp.Err
	GetOAuth2TokenByaccountId(accountId string) (*model.OAuth2Token, *resp.Err)
	DeleteOAuth2Token(accountId string) *resp.Err
}

type account struct {
	db dbclient.DbClient
}

func NewAccount(db dbclient.DbClient) Account {
	return &account{
		db: db,
	}
}

func (r *account) Add(acc *model.Account) (*model.Account, *resp.Err) {
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
				return nil, resp.Error(http.StatusInternalServerError, "account with the given nickname already exists", []interface{}{pqErr.Detail})
			}
		}
		log.Printf("failed to execute db.Exec ADD_ACCOUNT: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{err.Error()})
	}

	return acc, nil
}

func (r *account) Delete(accountId uuid.UUID) *resp.Err {
	_, err := r.db.Exec(DELETE_ACCOUNT, time.Now(), accountId)
	if err != nil {
		log.Printf("failed to execute db.Exec DELETE_ACCOUNT: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{err.Error()})
	}
	return nil
}

func (r *account) Find() ([]*model.Account, *resp.Err) {
	rows, err := r.db.Query(FIND_ACCOUNTS)
	if err != nil {
		log.Printf("failed to execute db.Query FIND_ACCOUNTS: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{err.Error()})
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
			return nil, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{scanErr.Error()})
		}

		if blocked.Valid {
			acc.Blocked = blocked.Time
		} else {
			acc.Blocked = time.Time{}
		}

		acc.Roles = make([]model.AccountRole, len(roleNames))
		for i, roleName := range roleNames {
			acc.Roles[i] = model.AccountRole{
				Id:   acc.Id,
				Name: roleName,
			}
		}

		accounts = append(accounts, &acc)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		log.Printf("error iterating over accounts: %v", rowsErr)
		return nil, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{rowsErr.Error()})
	}

	return accounts, nil
}

func (r *account) GetByEmail(email string) (*model.Account, *resp.Err) {
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
			return nil, resp.Error(http.StatusInternalServerError, "account not found", []interface{}{sql.ErrNoRows})
		}
		log.Printf("failed to scan rows GET_ACCOUNT_BY_EMAIL: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{err.Error()})
	}

	if blocked.Valid {
		acc.Blocked = blocked.Time
	} else {
		acc.Blocked = time.Time{}
	}

	acc.Roles = make([]model.AccountRole, len(roleNames))
	for i, roleName := range roleNames {
		acc.Roles[i] = model.AccountRole{
			Id:   acc.Id,
			Name: roleName,
		}
	}

	return &acc, nil
}

func (r *account) GetById(id uuid.UUID) (*model.Account, *resp.Err) {
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
			return nil, resp.Error(http.StatusInternalServerError, "account not found", []interface{}{sql.ErrNoRows})
		}
		log.Printf("failed to scan rows GET_ACCOUNT_BY_ID: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{err.Error()})
	}

	if blocked.Valid {
		acc.Blocked = blocked.Time
	} else {
		acc.Blocked = time.Time{}
	}

	acc.Roles = make([]model.AccountRole, len(roleNames))
	for i, roleName := range roleNames {
		acc.Roles[i] = model.AccountRole{
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

func (r *account) Update(acc *model.Account) (*model.Account, *resp.Err) {
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
		return nil, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{err.Error()})
	}

	return acc, nil
}

func (r *account) UpdatePassword(accountId uuid.UUID, newPassword string) *resp.Err {
	_, err := r.db.Exec(
		EDIT_ACCOUNT_PASSWORD,
		newPassword,
		time.Now(),
		accountId,
	)
	if err != nil {
		log.Printf("failed to execute db.Exec EDIT_ACCOUNT_PASSWORD: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{err.Error()})
	}

	return nil
}

func (r *account) AddAPIKey(apiKey *model.APIKey) (*model.APIKey, *resp.Err) {
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
		return nil, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{err.Error()})
	}

	return apiKey, nil
}

func (r *account) DeleteAPIKey(id uuid.UUID) *resp.Err {
	_, err := r.db.Exec(DELETE_APIKEY, id)
	if err != nil {
		log.Printf("failed to execute db.Exec DELETE_APIKEY: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{err.Error()})
	}

	return nil
}

func (r *account) GetAPIKeyById(id uuid.UUID) (*model.APIKey, *resp.Err) {
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
			return nil, resp.Error(http.StatusInternalServerError, "API key not found", []interface{}{sql.ErrNoRows})
		}
		log.Printf("failed to execute row.Scan GET_APIKEY_BY_Id: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{err.Error()})
	}

	if expiresAt.Valid {
		apiKey.ExpiresAt = expiresAt.Time
	} else {
		apiKey.ExpiresAt = time.Time{}
	}

	return &apiKey, nil
}

func (r *account) GetAPIKeyByKey(key string) (*model.APIKey, *resp.Err) {
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
			return nil, resp.Error(http.StatusInternalServerError, "API key not found", []interface{}{sql.ErrNoRows})
		}
		log.Printf("failed to execute row.Scan GET_APIKEY_BY_KEY: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{err.Error()})
	}

	if expiresAt.Valid {
		apiKey.ExpiresAt = expiresAt.Time
	} else {
		apiKey.ExpiresAt = time.Time{}
	}

	return &apiKey, nil
}

func (r *account) AddAccountRole(accountId uuid.UUID, role string) (*model.AccountRole, *resp.Err) {
	_, err := r.db.Exec(ADD_ACCOUNT_ROLE, accountId, role)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" {
				log.Printf("duplicate key error on ADD_ACCOUNT: %v", pqErr.Detail)
				return nil, resp.Error(http.StatusInternalServerError, "this role is already assigned to the account", []interface{}{pqErr.Detail})
			}
		}
		log.Printf("failed to execute ADD_ACCOUNT_ROLE: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{err.Error()})
	}
	res := model.AccountRole{
		Id:   accountId,
		Name: role,
	}
	return &res, nil
}

func (r *account) DeleteAccountRoleById(accountId uuid.UUID) *resp.Err {
	_, err := r.db.Exec(DELETE_ACCOUNT_ROLE_BY_ID, accountId)
	if err != nil {
		log.Printf("failed to execute DELETE_ACCOUNT_ROLE: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{err.Error()})
	}
	return nil
}

func (r *account) DeleteAccountRoleByName(role string) *resp.Err {
	_, err := r.db.Exec(DELETE_ACCOUNT_ROLE_BY_NAME, role)
	if err != nil {
		log.Printf("failed to execute DELETE_ACCOUNT_ROLE: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{err.Error()})
	}
	return nil
}

func (r *account) FindRolesByAccount(accountId uuid.UUID) ([]model.AccountRole, *resp.Err) {
	rows, err := r.db.Query(FIND_ROLES_BY_ACCOUNT_Id, accountId)
	if err != nil {
		log.Printf("failed to execute db.Query FIND_ROLES_BY_ACCOUNT_Id: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{err.Error()})
	}
	defer rows.Close()

	var roles []model.AccountRole
	for rows.Next() {
		var role model.AccountRole
		if scanErr := rows.Scan(&role.Name); scanErr != nil {
			log.Printf("failed to scan rows FIND_ROLES_BY_ACCOUNT_Id: %v", scanErr)
			return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{scanErr.Error()})
		}
		role.Id = accountId
		roles = append(roles, role)
	}

	if rowsErr := rows.Err(); rowsErr != nil {
		log.Printf("error while iterating over roles: %v", rowsErr)
		return nil, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{rowsErr.Error()})
	}

	return roles, nil
}

func (r *account) AddOAuth2Token(accountId string, token *model.OAuth2Token) *resp.Err {
	_, err := r.db.Exec(ADD_OAUTH2_TOKEN, accountId, token.AccessToken, token.RefreshToken, token.Expiry)
	if err != nil {
		log.Printf("failed to add OAuth2 token: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to add OAuth2 token", []interface{}{err.Error()})
	}
	return nil
}

func (r *account) GetOAuth2TokenByaccountId(accountId string) (*model.OAuth2Token, *resp.Err) {
	row := r.db.QueryRow(GET_OAUTH2_TOKEN, accountId)
	var token model.OAuth2Token
	err := row.Scan(&token.AccessToken, &token.RefreshToken, &token.Expiry)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, resp.Error(http.StatusNotFound, "OAuth2 token not found", []interface{}{err.Error()})
		}
		log.Printf("failed to get OAuth2 token: %v", err)
		return nil, resp.Error(http.StatusInternalServerError, "failed to get OAuth2 token", []interface{}{err.Error()})
	}
	return &token, nil
}

func (r *account) DeleteOAuth2Token(accountId string) *resp.Err {
	_, err := r.db.Exec(DELETE_OAUTH2_TOKEN, accountId)
	if err != nil {
		log.Printf("failed to delete OAuth2 token: %v", err)
		return resp.Error(http.StatusInternalServerError, "failed to delete OAuth2 token", []interface{}{err.Error()})
	}
	return nil
}
