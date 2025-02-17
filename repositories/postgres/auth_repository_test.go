package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	model "github.com/demkowo/auth/models"
	dbclient "github.com/demkowo/dbclient/client"
	"github.com/demkowo/utils/resp"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

var (
	errMap    map[string]error
	db        dbclient.DbClient
	a         *account
	apiKeys   pq.StringArray
	roles     pq.StringArray
	expiresAt sql.NullTime
	blocked   sql.NullTime

	pqError = &pq.Error{
		Code:    "23505",
		Message: "duplicate key value violates unique constraint",
		Detail:  "Key (nickname)=(test) already exists.",
	}

	acc        model.Account
	defaultAcc = model.Account{
		Id:       uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Nickname: "admin",
		Email:    "admin@admin.com",
		Password: "secretHashedPass",
		Roles:    make([]model.AccountRole, len(roles)),
		APIKeys:  make([]model.APIKey, len(apiKeys)),
		Created:  time.Now(),
		Updated:  time.Now(),
		Blocked:  time.Time{},
		Deleted:  false,
	}

	apiKey        model.APIKey
	defaultApiKey = model.APIKey{
		Id:        uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Key:       "someStrangeString",
		AccountId: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99123472e3"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now(),
	}

	role = model.AccountRole{
		Id:   uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Name: "admin",
	}

	token = model.OAuth2Token{
		AccessToken:  "validtoken",
		RefreshToken: "validNewToken",
		Expiry:       time.Now(),
	}

	tableExists                 = sql.NullString{String: "to_regclass", Valid: true}
	accountTableExistMock       = dbclient.Mock{Query: ACCOUNT_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{sql.NullString{}}}}
	createAccountTableMock      = dbclient.Mock{Query: CREATE_ACCOUNT_TABLE, Args: []interface{}{}, Columns: []string{"id", "nickname", "email", "password", "created", "updated", "blocked", "deleted"}, Rows: [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, blocked, acc.Deleted}}}
	accountRolesTableExistMock  = dbclient.Mock{Query: ACCOUNT_ROLES_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{sql.NullString{}}}}
	createAccountRolesTableMock = dbclient.Mock{Query: CREATE_ACCOUNT_ROLES_TABLE, Args: []interface{}{}, Columns: []string{"id", "name"}, Rows: [][]interface{}{{role.Id, role.Name}}}
	apiKeysTableExistMock       = dbclient.Mock{Query: APIKEY_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{sql.NullString{}}}}
	createApiKeyTableMock       = dbclient.Mock{Query: CREATE_APIKEY_TABLE, Args: []interface{}{}, Columns: []string{"id", "key", "account_id", "created_at", "expires_at"}, Rows: [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}}}
	oauth2TokensTableExistMock  = dbclient.Mock{Query: OAUTH2_TOKENS_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{sql.NullString{}}}}
	createOAuth2TokensTableMock = dbclient.Mock{Query: CREATE_OAUTH2_TOKENS_TABLE, Args: []interface{}{}, Columns: []string{"account_id", "access_token", "refresh_token", "expiry"}, Rows: [][]interface{}{{acc.Id, "access_token", "refresh_token", acc.ExpiresAt}}}
)

func TestMain(m *testing.M) {
	dbclient.StartMock()

	db, err := dbclient.Open("postgres", os.Getenv("DB_CLIENT"))
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	a = &account{db: db}

	os.Exit(m.Run())
}

func clearMock() {
	acc = defaultAcc
	apiKey = defaultApiKey
	apiKeys = pq.StringArray{}
	roles = pq.StringArray{}
	expiresAt = sql.NullTime{}
	blocked = sql.NullTime{}
	errMap = make(map[string]error)
}

func Test_NewAccount_Success(t *testing.T) {
	clearMock()

	res := NewAccount(db)

	if assert.NotNil(t, res) {
		accStruct, ok := res.(*account)
		assert.Equal(t, ok, true)
		assert.Equal(t, accStruct.db, db)
	}
}

func Test_CreateTables_Success(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(createApiKeyTableMock)
	dbclient.AddMock(oauth2TokensTableExistMock)
	dbclient.AddMock(createOAuth2TokensTableMock)

	err := a.CreateTables()

	assert.Nil(t, err)
}

func Test_CreateTables_isAccountTableExistError(t *testing.T) {
	dbclient.AddMock(dbclient.Mock{
		Query: ACCOUNT_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{"invalidDataType"}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, "type mismatch for column 'to_regclass': expected sql.NullString, got string")
}

func Test_CreateTables_createAccountTableError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(dbclient.Mock{
		Query: CREATE_ACCOUNT_TABLE, Args: []interface{}{"invalidArg"},
		Columns: []string{"id", "nickname", "email", "password", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, `number of arguments in mock can't be higher than number of arguments in method:
[invalidArg]
[]`)
}

func Test_CreateTables_createAccountTableAlreadyExists(t *testing.T) {
	dbclient.AddMock(dbclient.Mock{
		Query: ACCOUNT_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{tableExists}},
	})
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(createApiKeyTableMock)

	err := a.CreateTables()

	assert.Nil(t, err)
}

func Test_CreateTables_isAccountRolesTableExistError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(dbclient.Mock{
		Query: ACCOUNT_ROLES_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{"invalidDataType"}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, "type mismatch for column 'to_regclass': expected sql.NullString, got string")
}

func Test_CreateTables_createAccountRolesTableError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(dbclient.Mock{
		Query: CREATE_ACCOUNT_ROLES_TABLE, Args: []interface{}{"invalidArg"}, Columns: []string{"id", "name"}, Rows: [][]interface{}{{role.Id, role.Name}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, `number of arguments in mock can't be higher than number of arguments in method:
[invalidArg]
[]`)
}

func Test_CreateTables_createAccountRolesTableAlreadyExists(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(dbclient.Mock{
		Query: ACCOUNT_ROLES_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{tableExists}},
	})
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(createApiKeyTableMock)

	err := a.CreateTables()

	assert.Nil(t, err)
}

func Test_CreateTables_isApiKeyTableExistError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(dbclient.Mock{
		Query: APIKEY_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{"invalidDataType"}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, "type mismatch for column 'to_regclass': expected sql.NullString, got string")
}

func Test_CreateTables_createApiKeyTableError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(dbclient.Mock{
		Query: CREATE_APIKEY_TABLE, Args: []interface{}{"invalidArg"}, Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, `number of arguments in mock can't be higher than number of arguments in method:
[invalidArg]
[]`)
}

func Test_CreateTables_createApiKeyTableAlreadyExists(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(dbclient.Mock{
		Query: APIKEY_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{tableExists}},
	})
	dbclient.AddMock(createApiKeyTableMock)

	err := a.CreateTables()

	assert.Nil(t, err)
}

func Test_CreateTables_isOAuth2TokensTableExistError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(createApiKeyTableMock)
	dbclient.AddMock(dbclient.Mock{
		Query: OAUTH2_TOKENS_TABLE_EXIST, Args: []interface{}{}, Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}},
	})
	dbclient.AddMock(createOAuth2TokensTableMock)

	err := a.CreateTables()

	assert.EqualError(t, err, `invalid destinations length`)
}

func Test_CreateTables_createOAuth2TokensTableError(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(createApiKeyTableMock)
	dbclient.AddMock(oauth2TokensTableExistMock)
	dbclient.AddMock(dbclient.Mock{
		Query: CREATE_OAUTH2_TOKENS_TABLE, Args: []interface{}{"invalidArg"}, Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}},
	})

	err := a.CreateTables()

	assert.EqualError(t, err, `number of arguments in mock can't be higher than number of arguments in method:
[invalidArg]
[]`)
}

func Test_CreateTables_createOAuth2TokensTableAlreadyExists(t *testing.T) {
	dbclient.AddMock(accountTableExistMock)
	dbclient.AddMock(createAccountTableMock)
	dbclient.AddMock(accountRolesTableExistMock)
	dbclient.AddMock(createAccountRolesTableMock)
	dbclient.AddMock(apiKeysTableExistMock)
	dbclient.AddMock(createApiKeyTableMock)
	dbclient.AddMock(oauth2TokensTableExistMock)
	dbclient.AddMock(dbclient.Mock{
		Query: CREATE_OAUTH2_TOKENS_TABLE, Args: []interface{}{}, Columns: []string{"to_regclass"}, Rows: [][]interface{}{{tableExists}},
	})

	err := a.CreateTables()

	assert.Nil(t, err)
}
func Test_Add_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT, Args: []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, nil, acc.Deleted},
	})

	account, err := a.Add(&acc)

	assert.Nil(t, err)
	assert.NotNil(t, account)
}

func Test_Add_accBlockedIsZero(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT, Args: []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},
	})

	account, err := a.Add(&acc)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, &acc.Blocked, &account.Blocked)
	}
}

func Test_Add_accBlockedIsNotZero(t *testing.T) {
	clearMock()

	acc.Blocked = time.Now()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT, Args: []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},
	})

	account, err := a.Add(&acc)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, &acc.Blocked, &account.Blocked)
	}
}
func Test_Add_DuplicatedNicknameError(t *testing.T) {
	clearMock()

	errMap["Exec"] = pqError

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT, Args: []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, nil, acc.Deleted},
		Error: errMap,
	})

	account, err := a.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "account with the given nickname already exists", []interface{}{pqError.Detail}), err)
}

func Test_Add_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT, Args: []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, nil, acc.Deleted},
		Error: errMap,
	})

	account, err := a.Add(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create account", []interface{}{"Exec error"}), err)
}

func Test_Delete_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: DELETE_ACCOUNT, Args: []interface{}{time.Now(), acc.Id}})

	err := a.Delete(acc.Id)

	assert.Nil(t, err)
}

func Test_Delete_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_ACCOUNT, Args: []interface{}{time.Now(), acc.Id},
		Error: errMap,
	})

	err := a.Delete(acc.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete account", []interface{}{"Exec error"}), err)
}

func Test_Find_Success(t *testing.T) {
	clearMock()

	acc.APIKeys = nil

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	accounts, err := a.Find()

	assert.Nil(t, err)
	assert.Equal(t, 1, len(accounts))
	assert.Equal(t, &acc, accounts[0])
}

func Test_Find_Error(t *testing.T) {
	clearMock()

	errMap["Query"] = errors.New("Query error")

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Error:   errMap,
	})

	accounts, err := a.Find()

	assert.Nil(t, accounts)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{"Query error"}), err)
}

func Test_Find_ScanError(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, acc.Blocked, acc.Deleted}},
		Error:   errMap,
	})

	accounts, err := a.Find()

	assert.Nil(t, accounts)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{"Scan error"}), err)
}

func Test_Find_blockedIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	blocked.Time = tn
	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	accounts, err := a.Find()

	assert.Nil(t, err)
	assert.Equal(t, tn, accounts[0].Blocked)
}

func Test_Find_blockedIsNotValid(t *testing.T) {
	clearMock()

	blocked.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	accounts, err := a.Find()

	assert.Nil(t, err)
	assert.Equal(t, time.Time{}, accounts[0].Blocked)
}

func Test_Find_CheckRoles(t *testing.T) {
	clearMock()

	roles = append(roles, "admin", "tester")

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	accounts, err := a.Find()

	assert.Nil(t, err)
	assert.Equal(t, []model.AccountRole{{Id: acc.Id, Name: "admin"}, {Id: acc.Id, Name: "tester"}}, accounts[0].Roles)
}

func Test_Find_RowsError(t *testing.T) {
	clearMock()

	errMap["Rows"] = errors.New("Rows error")

	dbclient.AddMock(dbclient.Mock{
		Query:   FIND_ACCOUNTS,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Error:   errMap,
	})

	accounts, err := a.Find()

	assert.Nil(t, accounts)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find accounts", []interface{}{"Rows error"}), err)
}

func Test_GetByEmail_Success(t *testing.T) {
	clearMock()

	acc.APIKeys = nil

	dbclient.AddMock(dbclient.Mock{
		Args:    []interface{}{acc.Email},
		Query:   GET_ACCOUNT_BY_EMAIL,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetByEmail(acc.Email)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, &acc, account)
	}
}

func Test_GetByEmail_Error(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{
		Query: GET_ACCOUNT_BY_EMAIL, Args: []interface{}{acc.Email},
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Error:   errMap,
	})

	account, err := a.GetByEmail(acc.Email)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"Scan error"}), err)
}

func Test_GetByEmail_NotFoundError(t *testing.T) {
	clearMock()

	errMap["Scan"] = sql.ErrNoRows

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Email}, Query: GET_ACCOUNT_BY_EMAIL,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Error:   errMap,
	})

	account, err := a.GetByEmail(acc.Email)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, fmt.Sprintf("account with email %s not found", acc.Email), []interface{}{sql.ErrNoRows.Error()}), err)
}

func Test_GetByEmail_blockedIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	blocked.Time = tn
	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Args:    []interface{}{acc.Email},
		Query:   GET_ACCOUNT_BY_EMAIL,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetByEmail(acc.Email)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, tn, account.Blocked)
	}
}

func Test_GetByEmail_blockedIsNotValid(t *testing.T) {
	clearMock()

	blocked.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Email}, Query: GET_ACCOUNT_BY_EMAIL,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetByEmail(acc.Email)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, time.Time{}, account.Blocked)
	}
}

func Test_GetByEmail_CheckRoles(t *testing.T) {
	clearMock()

	roles = append(roles, "admin", "tester")

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Email}, Query: GET_ACCOUNT_BY_EMAIL,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetByEmail(acc.Email)

	assert.Nil(t, err)
	assert.Equal(t, []model.AccountRole{{Id: acc.Id, Name: "admin"}, {Id: acc.Id, Name: "tester"}}, account.Roles)
}

func Test_GetById_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Id}, Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_GetById_Error(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Id}, Query: GET_ACCOUNT_BY_ID,
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Error:   errMap,
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get account", []interface{}{"Scan error"}), err)
}

func Test_GetById_NotFoundError(t *testing.T) {
	clearMock()

	errMap["Scan"] = sql.ErrNoRows

	dbclient.AddMock(dbclient.Mock{
		Query: GET_ACCOUNT_BY_ID, Args: []interface{}{acc.Id},
		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Error:   errMap,
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "account not found", []interface{}{sql.ErrNoRows}), err)
}

func Test_GetById_blockedIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	blocked.Time = tn
	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Id}, Query: GET_ACCOUNT_BY_ID,
		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, tn, account.Blocked)
	}
}

func Test_GetById_blockedIsNotValid(t *testing.T) {
	clearMock()

	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Id}, Query: GET_ACCOUNT_BY_ID,
		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, time.Time{}, account.Blocked)
	}
}

func Test_GetById_CheckRoles(t *testing.T) {
	clearMock()

	roles = append(roles, "admin", "tester")

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Id}, Query: GET_ACCOUNT_BY_ID,
		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, []model.AccountRole{{Id: acc.Id, Name: "admin"}, {Id: acc.Id, Name: "tester"}}, account.Roles)
}

func Test_GetById_CheckApiKeys(t *testing.T) {
	clearMock()

	apiKeys = append(apiKeys, "key1", "key2")

	dbclient.AddMock(dbclient.Mock{
		Args: []interface{}{acc.Id}, Query: GET_ACCOUNT_BY_ID,
		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows:    [][]interface{}{{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted}},
	})

	account, err := a.GetById(acc.Id)

	assert.Nil(t, err)
	assert.Equal(t, []model.APIKey{
		{AccountId: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Key: "key1"},
		{AccountId: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Key: "key2"},
	}, account.APIKeys)
}

func Test_Update_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT, Args: []interface{}{acc.Email, nil, acc.Updated, acc.Id},
		Columns: []string{"email", "blocked", "updated", "id"},
		Rows:    [][]interface{}{{acc.Email, blocked, acc.Updated, acc.Id}},
	})

	account, err := a.Update(&acc)

	assert.Nil(t, err)
	assert.Equal(t, &acc, account)
}

func Test_Update_accBlockedIsZero(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT, Args: []interface{}{acc.Email, acc.Blocked, acc.Updated, acc.Id},
		Columns: []string{"email", "blocked", "updated", "id"},
		Rows:    [][]interface{}{{acc.Email, blocked, acc.Updated, acc.Id}},
	})

	account, err := a.Update(&acc)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, time.Time{}, account.Blocked)
	}
}

func Test_Update_accBlockedIsNotZero(t *testing.T) {
	clearMock()

	tn := time.Now()
	acc.Blocked = tn

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT, Args: []interface{}{acc.Email, acc.Blocked, acc.Updated, acc.Id},
		Columns: []string{"email", "blocked", "updated", "id"},
		Rows:    [][]interface{}{{acc.Email, blocked, acc.Updated, acc.Id}},
	})

	account, err := a.Update(&acc)

	assert.Nil(t, err)
	if assert.NotNil(t, account) {
		assert.Equal(t, tn, account.Blocked)
	}
}

func Test_Update_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT, Args: []interface{}{acc.Email, nil, acc.Updated, acc.Id},
		Columns: []string{"email", "blocked", "updated", "id"},
		Error:   errMap,
	})

	account, err := a.Update(&acc)

	assert.Nil(t, account)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to update account", []interface{}{"Exec error"}), err)
}

func Test_UpdatePassword_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: EDIT_ACCOUNT_PASSWORD, Args: []interface{}{"newPassword", time.Now(), acc.Id}})

	err := a.UpdatePassword(acc.Id, "newPassword")

	assert.Nil(t, err)
}

func Test_UpdatePassword_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT_PASSWORD,
		Args:  []interface{}{"newPassword", time.Now(), acc.Id},
		Error: errMap,
	})

	err := a.UpdatePassword(acc.Id, "newPassword")

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to change password", []interface{}{"Exec error"}), err)
}

func Test_AddAPIKey_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: ADD_APIKEY, Args: []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}})

	key, err := a.AddAPIKey(&apiKey)

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func Test_AddAPIKey_apiKeyExpiresAtIsZero(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Time{}

	dbclient.AddMock(dbclient.Mock{Query: ADD_APIKEY, Args: []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}})

	apiKey, err := a.AddAPIKey(&apiKey)

	assert.Nil(t, err)
	assert.Equal(t, time.Time{}, apiKey.ExpiresAt)
}

func Test_AddAPIKey_apiKeyExpiresAtIsNotZero(t *testing.T) {
	clearMock()

	tn := time.Now()
	apiKey.ExpiresAt = tn

	dbclient.AddMock(dbclient.Mock{Query: ADD_APIKEY, Args: []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt}})

	apiKey, err := a.AddAPIKey(&apiKey)

	assert.Nil(t, err)
	assert.Equal(t, tn, apiKey.ExpiresAt)
}

func Test_AddAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_APIKEY, Args: []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt},
		Error: errMap,
	})

	apiKey, err := a.AddAPIKey(&apiKey)

	assert.Nil(t, apiKey)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to create API key", []interface{}{"Exec error"}), err)
}

func Test_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: DELETE_APIKEY, Args: []interface{}{apiKey.Id}})

	err := a.DeleteAPIKey(apiKey.Id)

	assert.Nil(t, err)
}

func Test_DeleteAPIKey_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{Query: DELETE_APIKEY, Args: []interface{}{apiKey.Id}, Error: errMap})

	err := a.DeleteAPIKey(apiKey.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete API key", []interface{}{"Exec error"}), err)
}

func Test_GetAPIKeyById_Success(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Time{}

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id, Args: []interface{}{apiKey.Id},
		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows:    [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt}},
	})

	key, err := a.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func Test_GetAPIKeyById_Error(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{Query: GET_APIKEY_BY_Id, Args: []interface{}{apiKey.Id}, Error: errMap})

	apiKey, err := a.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, apiKey)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"Scan error"}), err)
}

func Test_GetAPIKeyById_NotFoundError(t *testing.T) {
	clearMock()

	errMap["Scan"] = sql.ErrNoRows

	dbclient.AddMock(dbclient.Mock{Query: GET_APIKEY_BY_Id, Args: []interface{}{apiKey.Id}, Error: errMap})

	apiKey, err := a.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, apiKey)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "API key not found", []interface{}{sql.ErrNoRows}), err)
}

func Test_GetAPIKeyById_ExpiresAtIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	expiresAt.Time = tn
	expiresAt.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id, Args: []interface{}{apiKey.Id},
		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows:    [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt}},
	})

	apiKey, err := a.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, err)
	assert.Equal(t, tn, apiKey.ExpiresAt)
}

func Test_GetAPIKeyById_ExpiresAtIsNotValid(t *testing.T) {
	clearMock()

	expiresAt.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id, Args: []interface{}{apiKey.Id},
		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows:    [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt}},
	})

	apiKey, err := a.GetAPIKeyById(apiKey.Id)

	assert.Nil(t, err)
	assert.Equal(t, time.Time{}, apiKey.ExpiresAt)
}

func Test_GetAPIKeyByKey_Success(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Time{}

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY, Args: []interface{}{apiKey.Key},
		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows:    [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt}},
	})

	key, err := a.GetAPIKeyByKey(apiKey.Key)

	assert.Nil(t, err)
	assert.Equal(t, &apiKey, key)
}

func Test_GetAPIKeyByKey_Error(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{Query: GET_APIKEY_BY_KEY, Args: []interface{}{apiKey.Key}, Error: errMap})

	apiKey, err := a.GetAPIKeyByKey(apiKey.Key)

	assert.Nil(t, apiKey)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get API Key", []interface{}{"Scan error"}), err)
}

func Test_GetAPIKeyByKey_NotFoundError(t *testing.T) {
	clearMock()

	errMap["Scan"] = sql.ErrNoRows

	dbclient.AddMock(dbclient.Mock{Query: GET_APIKEY_BY_KEY, Args: []interface{}{apiKey.Key}, Error: errMap})

	apiKey, err := a.GetAPIKeyByKey(apiKey.Key)

	assert.Nil(t, apiKey)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "API key not found", []interface{}{sql.ErrNoRows}), err)
}

func Test_GetAPIKeyByKey_expiresAtIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	expiresAt.Time = tn
	expiresAt.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY, Args: []interface{}{apiKey.Key},
		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows:    [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt}},
	})

	apiKey, err := a.GetAPIKeyByKey(apiKey.Key)

	assert.Nil(t, err)
	assert.Equal(t, tn, apiKey.ExpiresAt)
}
func Test_GetAPIKeyByKey_expiresAtIsNotValid(t *testing.T) {
	clearMock()

	expiresAt.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY, Args: []interface{}{apiKey.Key},
		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows:    [][]interface{}{{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt}},
	})

	apiKey, err := a.GetAPIKeyByKey(apiKey.Key)

	assert.Nil(t, err)
	assert.Equal(t, time.Time{}, apiKey.ExpiresAt)
}

func Test_AddAccountRole_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: ADD_ACCOUNT_ROLE, Args: []interface{}{role.Id, role.Name}})

	roles, err := a.AddAccountRole(role.Id, role.Name)

	assert.Nil(t, err)
	assert.Equal(t, &role, roles)
}

func Test_AddAccountRole_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{Query: ADD_ACCOUNT_ROLE, Args: []interface{}{role.Id, role.Name}, Error: errMap})

	roles, err := a.AddAccountRole(role.Id, role.Name)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to add role to account", []interface{}{"Exec error"}), err)
}

func Test_AddAccountRole_DuplicatedRoleError(t *testing.T) {
	clearMock()

	errMap["Exec"] = pqError

	dbclient.AddMock(dbclient.Mock{Query: ADD_ACCOUNT_ROLE, Args: []interface{}{role.Id, role.Name}, Error: errMap})

	roles, err := a.AddAccountRole(role.Id, role.Name)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "this role is already assigned to the account", []interface{}{pqError.Detail}), err)
}

func Test_DeleteAccountRoleById_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: DELETE_ACCOUNT_ROLE_BY_ID, Args: []interface{}{role.Id}})

	err := a.DeleteAccountRoleById(role.Id)

	assert.Nil(t, err)
}

func Test_DeleteAccountRoleById_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{Query: DELETE_ACCOUNT_ROLE_BY_ID, Args: []interface{}{role.Id}, Error: errMap})

	err := a.DeleteAccountRoleById(role.Id)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{"Exec error"}), err)
}

func Test_DeleteAccountRoleByName_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{Query: DELETE_ACCOUNT_ROLE_BY_NAME, Args: []interface{}{role.Name}})

	err := a.DeleteAccountRoleByName(role.Name)

	assert.Nil(t, err)
}

func Test_DeleteAccountRoleByName_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{Query: DELETE_ACCOUNT_ROLE_BY_NAME, Args: []interface{}{role.Name}, Error: errMap})

	err := a.DeleteAccountRoleByName(role.Name)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete role from account", []interface{}{"Exec error"}), err)
}

func Test_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id, Args: []interface{}{role.Id}, Columns: []string{"name"}, Rows: [][]interface{}{{"admin"}},
	})

	roles, err := a.FindRolesByAccount(role.Id)

	assert.Nil(t, err)
	assert.Equal(t, role, roles[0])
}

func Test_FindRolesByAccount_Error(t *testing.T) {
	clearMock()

	errMap["Query"] = errors.New("Query error")

	dbclient.AddMock(dbclient.Mock{Query: FIND_ROLES_BY_ACCOUNT_Id, Args: []interface{}{role.Id}, Error: errMap})

	roles, err := a.FindRolesByAccount(role.Id)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"Query error"}), err)
}

func Test_FindRolesByAccount_ScanError(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id, Args: []interface{}{role.Id},
		Columns: []string{"role_name"}, Rows: [][]interface{}{{"admin"}},
		Error: errMap,
	})

	roles, err := a.FindRolesByAccount(role.Id)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"Scan error"}), err)
}

func Test_FindRolesByAccount_CheckRoles(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id, Args: []interface{}{role.Id}, Columns: []string{"name"}, Rows: [][]interface{}{{"admin"}}})

	roles, err := a.FindRolesByAccount(role.Id)

	assert.Nil(t, err)
	assert.Equal(t, role, roles[0])
}

func Test_FindRolesByAccount_RowsError(t *testing.T) {
	clearMock()

	errMap["Rows"] = errors.New("Rows error")

	dbclient.AddMock(dbclient.Mock{Query: FIND_ROLES_BY_ACCOUNT_Id, Args: []interface{}{role.Id}, Error: errMap})

	roles, err := a.FindRolesByAccount(role.Id)

	assert.Nil(t, roles)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to find roles", []interface{}{"Rows error"}), err)
}

func Test_AddOAuth2Token_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String(), token.AccessToken, token.RefreshToken, token.Expiry},
		Columns: []string{"account_id", "access_token", "refresh_token", "expiry"}})

	err := a.AddOAuth2Token(acc.Id.String(), &token)

	assert.Nil(t, err)
}

func Test_AddOAuth2Token_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String(), token.AccessToken, token.RefreshToken, token.Expiry},
		Columns: []string{"account_id", "access_token", "refresh_token", "expiry"}, Error: errMap})

	err := a.AddOAuth2Token(acc.Id.String(), &token)

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to add OAuth2 token", []interface{}{"Exec error"}), err)
}

func Test_GetOAuth2TokenByaccountId_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String()},
		Columns: []string{"access_token", "refresh_token", "expiry"}, Rows: [][]interface{}{{token.AccessToken, token.RefreshToken, token.Expiry}}})

	oAuthToken, err := a.GetOAuth2TokenByaccountId(acc.Id.String())

	assert.Nil(t, err)
	assert.Equal(t, &token, oAuthToken)
}

func Test_GetOAuth2TokenByaccountId_NotFoundError(t *testing.T) {
	clearMock()

	errMap["Scan"] = sql.ErrNoRows

	dbclient.AddMock(dbclient.Mock{
		Query: GET_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String()}, Error: errMap,
		Columns: []string{"access_token", "refresh_token", "expiry"}, Rows: [][]interface{}{{token.AccessToken, token.RefreshToken, token.Expiry}}})

	oAuthToken, err := a.GetOAuth2TokenByaccountId(acc.Id.String())

	assert.Nil(t, oAuthToken)
	assert.Equal(t, resp.Error(http.StatusNotFound, "OAuth2 token not found", []interface{}{"sql: no rows in result set"}), err)
}

func Test_GetOAuth2TokenByaccountId_ScanError(t *testing.T) {
	clearMock()

	errMap["Scan"] = errors.New("Scan error")

	dbclient.AddMock(dbclient.Mock{
		Query: GET_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String()}, Error: errMap,
		Columns: []string{"access_token", "refresh_token", "expiry"}, Rows: [][]interface{}{{token.AccessToken, token.RefreshToken, token.Expiry}}})

	oAuthToken, err := a.GetOAuth2TokenByaccountId(acc.Id.String())

	assert.Nil(t, oAuthToken)
	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to get OAuth2 token", []interface{}{"Scan error"}), err)
}

func Test_DeleteOAuth2Token_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String()},
		Columns: []string{"access_token", "refresh_token", "expiry"}})

	err := a.DeleteOAuth2Token(acc.Id.String())

	assert.Nil(t, err)
}

func Test_DeleteOAuth2Token_Error(t *testing.T) {
	clearMock()

	errMap["Exec"] = errors.New("Exec error")

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_OAUTH2_TOKEN, Args: []interface{}{acc.Id.String()},
		Columns: []string{"access_token", "refresh_token", "expiry"}, Error: errMap})

	err := a.DeleteOAuth2Token(acc.Id.String())

	assert.Equal(t, resp.Error(http.StatusInternalServerError, "failed to delete OAuth2 token", []interface{}{"Exec error"}), err)
}
