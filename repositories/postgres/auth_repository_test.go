package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	model "github.com/demkowo/auth/models"
	dbclient "github.com/demkowo/dbclient/client"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	db            dbclient.DbClient
	err           error
	a             *account
	pqStringArray pq.StringArray
	apiKeys       pq.StringArray
	roles         pq.StringArray
	sqlNullTime   sql.NullTime
	expiresAt     sql.NullTime
	blocked       sql.NullTime

	expectedValue = make(map[string]interface{})
	acc           model.Account

	defaultAcc = model.Account{
		Id:       uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Nickname: "admin",
		Email:    "admin@admin.com",
		Password: "secretHashedPass",
		Roles:    nil,
		APIKeys:  nil,
		Created:  time.Now(),
		Updated:  time.Now(),
		Blocked:  time.Time{},
		Deleted:  false,
	}

	apiKey = model.APIKey{
		Id:        uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Key:       "someStrangeString",
		AccountId: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99123472e3"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now(),
	}

	accountRoles = model.AccountRoles{
		Id:   uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"),
		Name: "admin",
	}

	pqError = &pq.Error{
		Code:    "23505",
		Message: "duplicate key value violates unique constraint",
		Detail:  "Key (nickname)=(test) already exists.",
	}
)

func TestMain(m *testing.M) {
	dbclient.StartMock()

	db, err = dbclient.Open("postgres", os.Getenv("DB_CLIENT"))
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	a = &account{db: db}

	os.Exit(m.Run())
}

func clearMock() {
	acc = defaultAcc
	apiKeys = pqStringArray
	roles = pqStringArray
	expiresAt = sqlNullTime
	blocked = sqlNullTime
}

func Test_NewAccount_Success(t *testing.T) {
	clearMock()
	res := NewAccount(db)

	if res == nil {
		t.Fatal("NewAccount() returned nil, expected a valid interface")
	}
	accStruct, ok := res.(*account)
	if !ok {
		t.Fatalf("NewAccount() returned a type that is not *account, got %T", res)
	}
	if accStruct.db != db {
		t.Fatalf("NewAccount() did not assign the correct db client, got: %v, expected: %v", accStruct.db, db)
	}
}

func Test_Add_blockedIsZero(t *testing.T) {
	clearMock()
	acc.Blocked = time.Time{}
	expectedValue["index"] = 6
	expectedValue["value"] = nil

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT,
		Args:  []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},

		ExpectedValue: expectedValue,
	})

	err := a.Add(&acc)

	if err != nil {
		t.Fatal("expected no errors")
	}
}

func Test_Add_blockedIsNotZero(t *testing.T) {
	clearMock()

	tn := time.Now()
	acc.Blocked = tn
	expectedValue["index"] = 6
	expectedValue["value"] = tn

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT,
		Args:  []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},

		ExpectedValue: expectedValue,
	})

	err := a.Add(&acc)

	if err != nil {
		t.Fatal("expected no errors")
	}
}
func Test_Add_DuplicatedRecord(t *testing.T) {
	clearMock()
	// TODO: make possible adding roles while creating an account

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT,
		Args:  []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, nil, acc.Deleted},

		Error: pqError,
	})

	err := a.Add(&acc)
	if err == nil {
		t.Fatal("expected to get error")
	}

	if err.Error() != errors.New("account with the given nickname already exists").Error() {
		t.Fatal("expected error response: 'account with the given nickname already exists' while received:", err)
	}
}

func Test_Add_ExecError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT,
		Args:  []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, nil, acc.Deleted},

		Error: errors.New("test error"),
	})

	err := a.Add(&acc)
	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to create account").Error() {
		t.Fatalf("expected error response:\n'failed to create account' while received:\n'%s'", err.Error())
	}
}

func Test_Add_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT,
		Args:  []interface{}{acc.Id, acc.Nickname, acc.Email, acc.Password, acc.Created, acc.Updated, nil, acc.Deleted},
	})

	err := a.Add(&acc)

	if err != nil {
		t.Fatal("expected no errors")
	}
}

func Test_Delete_Error(t *testing.T) {
	clearMock()
	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_ACCOUNT,
		Args:  []interface{}{time.Now(), acc.Id},

		Error: errors.New("test error"),
	})

	err := a.Delete(acc.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to delete account").Error() {
		t.Fatalf("expected error response:\n'failed to delete account' while received:\n'%s'", err.Error())
	}
}

func Test_Delete_Success(t *testing.T) {
	clearMock()
	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_ACCOUNT,
		Args:  []interface{}{time.Now(), acc.Id},
	})

	err := a.Delete(acc.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_Find_QueryError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},
			{uuid.New(), "test", "test@test.com", "pass", roles, time.Now(), time.Now(), time.Time{}, false},
			{uuid.New(), "asd", "asd@asd.com", "pass", roles, time.Now(), time.Now(), time.Time{}, false},
		},

		Error: errors.New("test error"),
	})

	_, err := a.Find()

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to find accounts").Error() {
		t.Fatal("expected error response: 'failed to find accounts' while received:", err)
	}
}

func Test_Find_ScanError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},
			{uuid.New(), "test", "test@test.com", "pass", roles, time.Now(), time.Now(), time.Time{}, false},
			{uuid.New(), "asd", "asd@asd.com", "pass", roles, time.Now(), time.Now(), time.Time{}, false},
		},

		ScanErr: errors.New("test error"),
	})

	_, err := a.Find()

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to find accounts, scan error").Error() {
		t.Fatal("expected error response: 'failed to find accounts, scan error' while received:", err)
	}
}

func Test_Find_blockedValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	blocked.Time = tn
	blocked.Valid = true
	expectedValue["index"] = 7
	expectedValue["value"] = &sql.NullTime{Valid: true, Time: tn}

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},

		ExpectedValue: expectedValue,
	})

	_, err := a.Find()

	if err != nil {
		t.Fatal("expected no errors")
	}
}

func Test_Find_blockedNotValid(t *testing.T) {
	clearMock()

	blocked.Valid = false
	expectedValue["index"] = 7
	expectedValue["value"] = &sql.NullTime{Valid: false, Time: time.Time{}}

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},

		ExpectedValue: expectedValue,
	})

	_, err := a.Find()

	if err != nil {
		t.Fatal("expected no errors")
	}
}

func Test_Find_CheckRoles(t *testing.T) {
	clearMock()

	roles = append(roles, "admin", "tester")
	expectedValue["index"] = 4
	expectedValue["value"] = &roles

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},

		ExpectedValue: expectedValue,
	})

	_, err := a.Find()

	if err != nil {
		t.Fatal("expected no errors")
	}
}

func Test_Find_RowsErrors(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
			{uuid.New(), "test", "test@test.com", "pass", roles, time.Now(), time.Now(), blocked, false},
			{uuid.New(), "asd", "asd@asd.com", "pass", roles, time.Now(), time.Now(), blocked, false},
		},

		RowsErr: errors.New("test error"),
	})

	_, err := a.Find()

	if err == nil {
		t.Fatal("expected to get error")
	}

	if err.Error() != errors.New("failed to find accounts, error in rows").Error() {
		t.Fatal("expected error response: 'failed to find accounts' while received:", err)
	}
}

func Test_Find_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ACCOUNTS,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
			{uuid.New(), "test", "test@test.com", "pass", roles, time.Now(), time.Now(), blocked, false},
			{uuid.New(), "asd", "asd@asd.com", "pass", roles, time.Now(), time.Now(), blocked, false},
		},
	})

	_, err := a.Find()

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_GetByEmail_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_ACCOUNT_BY_EMAIL,
		Args:  []interface{}{acc.Email},

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},

		Error: errors.New("test error"),
	})

	_, err := a.GetByEmail(acc.Email)

	if err == nil {
		t.Fatal("expected to get error")
	}
}

func Test_GetByEmail_NoAccountError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Email},
		Query: GET_ACCOUNT_BY_EMAIL,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, acc.Blocked, acc.Deleted},
		},

		Error: sql.ErrNoRows,
	})

	_, err := a.GetByEmail(acc.Email)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != fmt.Errorf("account with email %s not found", acc.Email).Error() {
		t.Fatalf("expected to get error 'account with email %s not found' while received '%v'", acc.Email, err)
	}
}

func Test_GetByEmail_BlockedValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	blocked.Time = tn
	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Email},
		Query: GET_ACCOUNT_BY_EMAIL,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetByEmail(acc.Email)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	if res.Blocked != tn {
		t.Fatalf("when blocked.Valid = true\nexpected value: %v\nreceived value: %v", tn, res.Blocked)
	}
}

func Test_GetByEmail_BlockedNotValid(t *testing.T) {
	clearMock()

	blocked.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Email},
		Query: GET_ACCOUNT_BY_EMAIL,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetByEmail(acc.Email)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedTime := time.Time{}
	if res.Blocked != expectedTime {
		t.Fatalf("when blocked.Valid = false\nexpected value: %v\nreceived value: %v", expectedTime, res.Blocked)
	}
}

func Test_GetByEmail_CheckRoles(t *testing.T) {
	clearMock()

	acc.Id = uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3")
	roles = append(roles, "admin", "tester")

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Email},
		Query: GET_ACCOUNT_BY_EMAIL,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetByEmail(acc.Email)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedRoles := []model.AccountRoles{
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "admin"},
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "tester"},
	}
	if !reflect.DeepEqual(res.Roles, expectedRoles) {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_GetByEmail_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Email},
		Query: GET_ACCOUNT_BY_EMAIL,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	_, err := a.GetByEmail(acc.Email)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_GetById_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Id},
		Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},

		Error: errors.New("test error"),
	})

	_, err := a.GetById(acc.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to get account").Error() {
		t.Fatalf("expected to get error 'failed to get account' while received '%v'", err)
	}
}

func Test_GetById_NoRowsError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_ACCOUNT_BY_ID,
		Args:  []interface{}{acc.Id},

		Columns: []string{"id", "nickname", "email", "password", "roles", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, acc.Created, acc.Updated, blocked, acc.Deleted},
		},

		Error: sql.ErrNoRows,
	})

	_, err := a.GetById(acc.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("account not found").Error() {
		t.Fatalf("expected to get error 'account not found' while received '%v'", err)
	}
}

func Test_GetById_BlockedValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	blocked.Time = tn
	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Id},
		Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetById(acc.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	if res.Blocked != tn {
		t.Fatalf("when blocked.Valid = true\nexpected value: %v\nreceived value: %v", tn, res.Blocked)
	}
}

func Test_GetById_BlockedNotValid(t *testing.T) {
	clearMock()

	blocked.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Id},
		Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetById(acc.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedTime := time.Time{}
	if res.Blocked != expectedTime {
		t.Fatalf("when blocked.Valid = false\nexpected value: %v\nreceived value: %v", expectedTime, res.Blocked)
	}
}

func Test_GetById_CheckRoles(t *testing.T) {
	clearMock()

	acc.Id = uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3")
	roles = append(roles, "admin", "tester")

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Id},
		Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetById(acc.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedRoles := []model.AccountRoles{
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "admin"},
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "tester"},
	}
	if !reflect.DeepEqual(res.Roles, expectedRoles) {
		t.Fatalf("roles in response are not as expected\nexpected: %v\nreceived: %v", expectedRoles, res.Roles)
	}
}

func Test_GetById_CheckApiKeys(t *testing.T) {
	// TODO: make possible fetching all info about apiKeys
	clearMock()

	apiKeys = append(apiKeys, "key1", "key2")

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Id},
		Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	res, err := a.GetById(acc.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedKeys := []model.APIKey{
		{Key: "key1", AccountId: acc.Id},
		{Key: "key2", AccountId: acc.Id},
	}
	if !reflect.DeepEqual(res.APIKeys, expectedKeys) {
		t.Fatalf("APIKeys in response are not as expected\nexpected: %v\nreceived: %v", expectedKeys, res.APIKeys)
	}
}

func Test_GetById_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Args:  []interface{}{acc.Id},
		Query: GET_ACCOUNT_BY_ID,

		Columns: []string{"id", "nickname", "email", "password", "roles", "api_keys", "created", "updated", "blocked", "deleted"},
		Rows: [][]interface{}{
			{acc.Id, acc.Nickname, acc.Email, acc.Password, roles, apiKeys, acc.Created, acc.Updated, blocked, acc.Deleted},
		},
	})

	_, err := a.GetById(acc.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_Update_BlockedIsZero(t *testing.T) {
	clearMock()

	acc.Blocked = time.Time{}
	expectedValue["index"] = 1
	expectedValue["value"] = nil

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT,
		Args:  []interface{}{acc.Email, acc.Blocked, acc.Updated, acc.Id},

		Columns: []string{"email", "blocked", "updated", "id"},
		Rows: [][]interface{}{
			{acc.Email, blocked, acc.Updated, acc.Id},
		},

		ExpectedValue: expectedValue,
	})

	err := a.Update(&acc)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_Update_BlockedIsNotZero(t *testing.T) {
	clearMock()

	tn := time.Now()
	acc.Blocked = tn
	expectedValue["index"] = 1
	expectedValue["value"] = tn

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT,
		Args:  []interface{}{acc.Email, acc.Blocked, acc.Updated, acc.Id},

		Columns: []string{"email", "blocked", "updated", "id"},
		Rows: [][]interface{}{
			{acc.Email, blocked, acc.Updated, acc.Id},
		},

		ExpectedValue: expectedValue,
	})

	err := a.Update(&acc)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_Update_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT,
		Args:  []interface{}{acc.Email, nil, acc.Updated, acc.Id},

		Columns: []string{"email", "blocked", "updated", "id"},
		Rows: [][]interface{}{
			{acc.Email, blocked, acc.Updated, acc.Id},
		},

		Error: errors.New("test error"),
	})

	err := a.Update(&acc)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to update account").Error() {
		t.Fatalf("expected to get error 'failed to update account' while received '%v'", err)
	}
}

func Test_Update_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT,
		Args:  []interface{}{acc.Email, nil, acc.Updated, acc.Id},

		Columns: []string{"email", "blocked", "updated", "id"},
		Rows: [][]interface{}{
			{acc.Email, blocked, acc.Updated, acc.Id},
		},
	})

	err := a.Update(&acc)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_UpdatePassword_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT_PASSWORD,
		Args:  []interface{}{"newPassword", time.Now(), acc.Id},

		Error: errors.New("test error"),
	})

	err := a.UpdatePassword(acc.Id, "newPassword")

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to change password").Error() {
		t.Fatalf("expected to get error 'failed to change password' while received '%v'", err)
	}
}

func Test_UpdatePassword_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: EDIT_ACCOUNT_PASSWORD,
		Args:  []interface{}{"newPassword", time.Now(), acc.Id},
	})

	err := a.UpdatePassword(acc.Id, "newPassword")

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_AddAPIKey_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_APIKEY,
		Args:  []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt},

		Error: errors.New("test error"),
	})

	err := a.AddAPIKey(&apiKey)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to create API key").Error() {
		t.Fatalf("expected to get error 'failed to create API key' while received '%v'", err)
	}
}

func Test_AddAPIKey_ExpiresIsZero(t *testing.T) {
	clearMock()

	apiKey.ExpiresAt = time.Time{}
	expectedValue["index"] = 4
	expectedValue["value"] = nil

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_APIKEY,
		Args:  []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt},

		ExpectedValue: expectedValue,
	})

	err := a.AddAPIKey(&apiKey)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}

}

func Test_AddAPIKey_ExpiresIsNotZero(t *testing.T) {
	clearMock()

	tn := time.Now()
	apiKey.ExpiresAt = tn
	expectedValue["index"] = 4
	expectedValue["value"] = tn

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_APIKEY,
		Args:  []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt},

		ExpectedValue: expectedValue,
	})

	err := a.AddAPIKey(&apiKey)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_AddAPIKey_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_APIKEY,
		Args:  []interface{}{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, apiKey.ExpiresAt},
	})

	err := a.AddAPIKey(&apiKey)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_DeleteAPIKey_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_APIKEY,
		Args:  []interface{}{apiKey.Key},

		Error: errors.New("test error"),
	})

	err := a.DeleteAPIKey(apiKey.Key)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to delete API key").Error() {
		t.Fatalf("expected to get error 'failed to delete API key' while received '%v'", err)
	}
}

func Test_DeleteAPIKey_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_APIKEY,
		Args:  []interface{}{apiKey.Key},
	})

	err := a.DeleteAPIKey(apiKey.Key)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_GetAPIKeyById_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id,
		Args:  []interface{}{apiKey.Id},

		Error: errors.New("test error"),
	})

	_, err := a.GetAPIKeyById(apiKey.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to get API Key").Error() {
		t.Fatalf("expected to get error 'failed to get API Key' while received '%v'", err)
	}
}

func Test_GetAPIKeyById_NotFound(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id,
		Args:  []interface{}{apiKey.Id},

		Error: sql.ErrNoRows,
	})

	_, err := a.GetAPIKeyById(apiKey.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("API key not found").Error() {
		t.Fatalf("expected to get error 'API key not found' while received '%v'", err)
	}
}

func Test_GetAPIKeyById_ExpiresAtIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	expiresAt.Time = tn
	expiresAt.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id,
		Args:  []interface{}{apiKey.Id},

		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{
			{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt},
		},
	})

	res, err := a.GetAPIKeyById(apiKey.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	if !reflect.DeepEqual(res.ExpiresAt, expiresAt.Time) {
		t.Fatalf("invalid value for expiresAt\nexpected: %v\nreceived: %v", res.ExpiresAt, expiresAt.Time)
	}
}

func Test_GetAPIKeyById_ExpiresAtIsNotValid(t *testing.T) {
	clearMock()

	expiresAt.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id,
		Args:  []interface{}{apiKey.Id},

		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{
			{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt},
		},
	})

	res, err := a.GetAPIKeyById(apiKey.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedTime := time.Time{}
	if !reflect.DeepEqual(res.ExpiresAt, expectedTime) {
		t.Fatalf("invalid value for expiresAt\nexpected: %v\nreceived: %v", res.ExpiresAt, expectedTime)
	}
}
func Test_GetAPIKeyById_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_Id,
		Args:  []interface{}{apiKey.Id},

		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{
			{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt},
		},
	})

	_, err := a.GetAPIKeyById(apiKey.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_GetAPIKeyByKey_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY,
		Args:  []interface{}{apiKey.Key},

		Error: errors.New("test error"),
	})

	_, err := a.GetAPIKeyByKey(apiKey.Key)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to get API Key").Error() {
		t.Fatalf("expected to get error 'failed to get API Key' while received '%v'", err)
	}
}

func Test_GetAPIKeyByKey_NotFound(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY,
		Args:  []interface{}{apiKey.Key},

		Error: sql.ErrNoRows,
	})

	_, err := a.GetAPIKeyByKey(apiKey.Key)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("API key not found").Error() {
		t.Fatalf("expected to get error 'API key not found' while received '%v'", err)
	}
}

func Test_GetAPIKeyByKey_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY,
		Args:  []interface{}{apiKey.Key},

		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{
			{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt},
		},
	})

	_, err := a.GetAPIKeyByKey(apiKey.Key)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_GetAPIKeyByKey_ExpiredAtIsValid(t *testing.T) {
	clearMock()

	tn := time.Now()
	expiresAt.Time = tn
	expiresAt.Valid = true

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY,
		Args:  []interface{}{apiKey.Key},

		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{
			{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt},
		},
	})

	res, err := a.GetAPIKeyByKey(apiKey.Key)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	if !reflect.DeepEqual(res.ExpiresAt, expiresAt.Time) {
		t.Fatalf("invalid value for expiresAt\nexpected: %v\nreceived: %v", res.ExpiresAt, expiresAt.Time)
	}
}
func Test_GetAPIKeyByKey_ExpiredAtIsNotValid(t *testing.T) {
	clearMock()

	expiresAt.Valid = false

	dbclient.AddMock(dbclient.Mock{
		Query: GET_APIKEY_BY_KEY,
		Args:  []interface{}{apiKey.Key},

		Columns: []string{"id", "key", "account_id", "created_at", "expires_at"},
		Rows: [][]interface{}{
			{apiKey.Id, apiKey.Key, apiKey.AccountId, apiKey.CreatedAt, expiresAt},
		},
	})

	res, err := a.GetAPIKeyByKey(apiKey.Key)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedTime := time.Time{}
	if !reflect.DeepEqual(res.ExpiresAt, expectedTime) {
		t.Fatalf("invalid value for expiresAt\nexpected: %v\nreceived: %v", res.ExpiresAt, expectedTime)
	}
}

func Test_AddAccountRole_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT_ROLE,
		Args:  []interface{}{accountRoles.Id, accountRoles.Name},

		Error: errors.New("test error"),
	})

	err := a.AddAccountRole(accountRoles.Id, accountRoles.Name)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to add role to account").Error() {
		t.Fatalf("expected to get error 'failed to add role to account' while received '%v'", err)
	}
}

func Test_AddAccountRole_DuplicateError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT_ROLE,
		Args:  []interface{}{accountRoles.Id, accountRoles.Name},

		Error: pqError,
	})

	err := a.AddAccountRole(accountRoles.Id, accountRoles.Name)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("this role is already assigned to the account").Error() {
		t.Fatalf("expected to get error 'this role is already assigned to the account' while received '%v'", err)
	}
}

func Test_AddAccountRole_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: ADD_ACCOUNT_ROLE,
		Args:  []interface{}{accountRoles.Id, accountRoles.Name},
	})

	err := a.AddAccountRole(accountRoles.Id, accountRoles.Name)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_DeleteAccountRole_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_ACCOUNT_ROLE,
		Args:  []interface{}{accountRoles.Id, accountRoles.Name},

		Error: pqError,
	})

	err := a.DeleteAccountRole(accountRoles.Id, accountRoles.Name)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to delete role from account").Error() {
		t.Fatalf("expected to get error 'failed to delete role from account' while received '%v'", err)
	}
}

func Test_DeleteAccountRole_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: DELETE_ACCOUNT_ROLE,
		Args:  []interface{}{accountRoles.Id, accountRoles.Name},
	})

	err := a.DeleteAccountRole(accountRoles.Id, accountRoles.Name)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}

func Test_FindRolesByAccount_Error(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id,
		Args:  []interface{}{accountRoles.Id},

		Error: errors.New("test error"),
	})

	_, err := a.FindRolesByAccount(accountRoles.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to find roles").Error() {
		t.Fatalf("expected to get error 'failed to find roles' while received '%v'", err)
	}
}

func Test_FindRolesByAccount_ScanError(t *testing.T) {
	clearMock()

	// TODO: make sure that if there are no rows and records, record not foud error will be send back
	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id,
		Args:  []interface{}{accountRoles.Id},

		Columns: []string{"role_name"},
		Rows: [][]interface{}{
			{accountRoles.Name},
		},

		ScanErr: errors.New("scan error"),
	})

	_, err := a.FindRolesByAccount(accountRoles.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to find roles").Error() {
		t.Fatalf("expected to get error 'failed to find roles' while received '%v'", err)
	}
}

func Test_FindRolesByAccount_CheckRoles(t *testing.T) {
	clearMock()

	acc.Id = uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3")
	roles = append(roles, "admin", "tester")

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id,
		Args:  []interface{}{accountRoles.Id},

		Columns: []string{"role_name"},
		Rows: [][]interface{}{
			{accountRoles.Name}, {"tester"},
		},
	})

	res, err := a.FindRolesByAccount(accountRoles.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
	expectedRoles := []model.AccountRoles{
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "admin"},
		{Id: uuid.MustParse("3a82ef35-6de8-4eaa-9f53-5a99645772e3"), Name: "tester"},
	}
	if !reflect.DeepEqual(res, expectedRoles) {
		t.Fatalf("invalid roles\nexpected: %v\nreceived: %v", expectedRoles, res)
	}
}

func Test_FindRolesByAccount_RowsError(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id,
		Args:  []interface{}{accountRoles.Id},

		RowsErr: errors.New("rows error"),
	})

	_, err := a.FindRolesByAccount(accountRoles.Id)

	if err == nil {
		t.Fatal("expected to get error")
	}
	if err.Error() != errors.New("failed to find roles").Error() {
		t.Fatalf("expected to get error 'failed to find roles' while received '%v'", err)
	}
}

func Test_FindRolesByAccount_Success(t *testing.T) {
	clearMock()

	dbclient.AddMock(dbclient.Mock{
		Query: FIND_ROLES_BY_ACCOUNT_Id,
		Args:  []interface{}{accountRoles.Id},
	})

	_, err := a.FindRolesByAccount(accountRoles.Id)

	if err != nil {
		t.Fatal("expected no errors while received:", err)
	}
}
