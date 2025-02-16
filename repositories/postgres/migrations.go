package postgres

import (
	"database/sql"
	"log"
)

const (
	ACCOUNT_TABLE_EXIST       = "SELECT to_regclass('public.account');"
	ACCOUNT_ROLES_TABLE_EXIST = "SELECT to_regclass('public.account_roles');"
	APIKEY_TABLE_EXIST        = "SELECT to_regclass('public.api_keys');"
	OAUTH2_TOKENS_TABLE_EXIST = "SELECT to_regclass('public.oauth2_tokens');"

	CREATE_ACCOUNT_TABLE = `
	CREATE TABLE IF NOT EXISTS public.account (
		id UUID PRIMARY KEY,
		nickname VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL UNIQUE,
		password VARCHAR(255) NOT NULL,
		created TIMESTAMPTZ NOT NULL,
		updated TIMESTAMPTZ NOT NULL,
		blocked TIMESTAMPTZ,
		deleted BOOLEAN NOT NULL DEFAULT FALSE,
		CONSTRAINT account_unique UNIQUE (nickname)
	);
	`

	CREATE_ACCOUNT_ROLES_TABLE = `
	CREATE TABLE IF NOT EXISTS public.account_roles (
		id UUID NOT NULL,
		name VARCHAR(255) NOT NULL UNIQUE,
		PRIMARY KEY (id)
	);
	`

	CREATE_APIKEY_TABLE = `
	CREATE TABLE IF NOT EXISTS public.api_keys (
		id UUID PRIMARY KEY,
		key TEXT NOT NULL UNIQUE,
		account_id UUID REFERENCES public.account(id) ON DELETE CASCADE,
		created_at TIMESTAMPTZ NOT NULL,
		expires_at TIMESTAMPTZ
	);
	`

	CREATE_OAUTH2_TOKENS_TABLE = `
	CREATE TABLE IF NOT EXISTS public.oauth2_tokens (
		account_id UUID REFERENCES public.account(id) ON DELETE CASCADE,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		expiry TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (account_id)
	);
	`
)

var (
	tableName sql.NullString
)

func (r *account) CreateTables() error {
	if err := isAccountTableExist(r); err != nil {
		return err
	}
	if err := createAccountTable(r); err != nil {
		return err
	}
	if err := isAccountRolesTableExist(r); err != nil {
		return err
	}
	if err := createAccountRolesTable(r); err != nil {
		return err
	}
	if err := isApiKeyTableExist(r); err != nil {
		return err
	}
	if err := createApiKeyTable(r); err != nil {
		return err
	}
	if err := isOAuth2TokensTableExist(r); err != nil {
		return err
	}
	if err := createOAuth2TokensTable(r); err != nil {
		return err
	}

	if !tableName.Valid {
		log.Println("table oauth2_tokens does not exist, creating it")
		if _, err := r.db.Exec(CREATE_OAUTH2_TOKENS_TABLE); err != nil {
			log.Printf("failed to create oauth2_tokens table: %v\n", err)
			return err
		}
	} else {
		log.Println("table oauth2_tokens already exists")
	}

	log.Println("All authentication-related tables are ready")
	return nil
}

func isAccountTableExist(r *account) error {
	err := r.db.QueryRow(ACCOUNT_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow ACCOUNT_TABLE_EXIST: %v\n", err)
		return err
	}
	return nil
}

func createAccountTable(r *account) error {
	if !tableName.Valid {
		log.Println("table account does not exist, creating it")
		if _, err := r.db.Exec(CREATE_ACCOUNT_TABLE); err != nil {
			log.Printf("failed to create account table: %v\n", err)
			return err
		}
	}

	log.Println("table account already exists")
	return nil
}

func isAccountRolesTableExist(r *account) error {
	err := r.db.QueryRow(ACCOUNT_ROLES_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow ACCOUNT_ROLES_TABLE_EXIST: %v\n", err)
		return err
	}
	return nil
}

func createAccountRolesTable(r *account) error {
	if !tableName.Valid {
		log.Println("table account_roles does not exist, creating it")
		if _, err := r.db.Exec(CREATE_ACCOUNT_ROLES_TABLE); err != nil {
			log.Printf("failed to create account_roles table: %v\n", err)
			return err
		}
	}
	log.Println("table account_roles already exists")
	return nil
}

func isApiKeyTableExist(r *account) error {
	err := r.db.QueryRow(APIKEY_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow APIKEY_TABLE_EXIST: %v\n", err)
		return err
	}
	return nil
}

func createApiKeyTable(r *account) error {
	if !tableName.Valid {
		log.Println("table api_keys does not exist, creating it")
		if _, err := r.db.Exec(CREATE_APIKEY_TABLE); err != nil {
			log.Printf("failed to create api_keys table: %v\n", err)
			return err
		}
	}
	log.Println("table api_keys already exists")
	return nil
}

func isOAuth2TokensTableExist(r *account) error {
	err := r.db.QueryRow(OAUTH2_TOKENS_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow OAUTH2_TOKENS_TABLE_EXIST: %v\n", err)
		return err
	}
	return nil
}

func createOAuth2TokensTable(r *account) error {
	if !tableName.Valid {
		log.Println("table api_keys does not exist, creating it")
		if _, err := r.db.Exec(CREATE_APIKEY_TABLE); err != nil {
			log.Printf("failed to create api_keys table: %v\n", err)
			return err
		}
	}
	log.Println("table api_keys already exists")
	return nil
}
