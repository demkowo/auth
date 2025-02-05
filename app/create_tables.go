package app

import (
	"database/sql"
	"log"

	dbclient "github.com/demkowo/dbclient/client"
)

const (
	ACCOUNT_TABLE_EXIST       = "SELECT to_regclass('public.account');"
	ACCOUNT_ROLES_TABLE_EXIST = "SELECT to_regclass('public.account_roles');"
	APIKEY_TABLE_EXIST        = "SELECT to_regclass('public.api_keys');"

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
		name VARCHAR(255) NOT NULL,
		PRIMARY KEY (id, name)
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
)

func CreateTables(db dbclient.DbClient) error {
	var tableName sql.NullString

	err := db.QueryRow(ACCOUNT_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow ACCOUNT_TABLE_EXIST: %v\n", err)
		return err
	}
	if !tableName.Valid {
		log.Println("table account does not exist, creating it")
		if _, err := db.Exec(CREATE_ACCOUNT_TABLE); err != nil {
			log.Printf("failed to create account table: %v\n", err)
			return err
		}
	} else {
		log.Println("table account already exists")
	}

	err = db.QueryRow(ACCOUNT_ROLES_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow ACCOUNT_ROLES_TABLE_EXIST: %v\n", err)
		return err
	}
	if !tableName.Valid {
		log.Println("table account_roles does not exist, creating it")
		if _, err := db.Exec(CREATE_ACCOUNT_ROLES_TABLE); err != nil {
			log.Printf("failed to create account_roles table: %v\n", err)
			return err
		}
	} else {
		log.Println("table account_roles already exists")
	}

	err = db.QueryRow(APIKEY_TABLE_EXIST).Scan(&tableName)
	if err != nil {
		log.Printf("failed to execute db.QueryRow APIKEY_TABLE_EXIST: %v\n", err)
		return err
	}
	if !tableName.Valid {
		log.Println("table api_keys does not exist, creating it")
		if _, err := db.Exec(CREATE_APIKEY_TABLE); err != nil {
			log.Printf("failed to create api_keys table: %v\n", err)
			return err
		}
	} else {
		log.Println("table api_keys already exists")
	}

	log.Println("All authentication-related tables are ready")
	return nil
}
