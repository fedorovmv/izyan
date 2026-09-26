package main

import (
	"database/sql"
	"fmt"

	"example.com/dep/vuln"
)

// The sink argument is populated by rows.Scan — the value comes from the
// database, so attacker control depends on who writes to the store:
// DATABASE provenance, not external-untrusted and not constant.
func main() {
	var db *sql.DB
	rows, _ := db.Query("select name from t")
	var s string
	if rows.Next() {
		_ = rows.Scan(&s)
	}
	fmt.Println(vuln.Parse(s))
}
