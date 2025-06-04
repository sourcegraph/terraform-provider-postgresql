package postgresql

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/lib/pq"
)

// testEnsureTestRoleExists creates the test role directly using DB connection
func testEnsureTestRoleExists(t *testing.T, roleName string) {
	client := testAccProvider.Meta().(*Client)
	db, err := client.Connect()
	if err != nil {
		t.Fatalf("Error connecting to postgres: %s", err)
	}

	// Check if role already exists
	var exists int
	err = db.QueryRow("SELECT 1 FROM pg_roles WHERE rolname = $1", roleName).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("Error checking if role exists: %s", err)
	}

	// If role doesn't exist, create it
	if err == sql.ErrNoRows {
		_, err = db.Exec(fmt.Sprintf("CREATE ROLE %s", pq.QuoteIdentifier(roleName)))
		if err != nil {
			t.Fatalf("Error creating role %s: %s", roleName, err)
		}
		t.Logf("Created test role: %s", roleName)
	}
}

func testEnsureTestRoleDestroyed(t *testing.T, roleName string) {
	client := testAccProvider.Meta().(*Client)
	db, err := client.Connect()
	if err != nil {
		t.Fatalf("Error connecting to postgres: %s", err)
	}

	// Check if role exists
	var exists int
	err = db.QueryRow("SELECT 1 FROM pg_roles WHERE rolname = $1", roleName).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("Error checking if role exists: %s", err)
	}

	// If role exists, drop it
	if err == nil {
		_, err = db.Exec(fmt.Sprintf("DROP ROLE %s", pq.QuoteIdentifier(roleName)))
		if err != nil {
			t.Fatalf("Error dropping role %s: %s", roleName, err)
		}
		t.Logf("Dropped test role: %s", roleName)
	}
}

func TestAccPostgresqlRoleAttribute_Basic(t *testing.T) {
	roleName := fmt.Sprintf("tf_test_role_%s", t.Name())

	configCreate := fmt.Sprintf(`
resource "postgresql_role_attribute" "test" {
	name = "%s"
	connection_limit = 10
	bypass_row_level_security = true
}`, roleName)

	configUpdate := fmt.Sprintf(`
resource "postgresql_role_attribute" "test" {
	name = "%s"
	connection_limit = 100
	bypass_row_level_security = false
	create_database = true
}`, roleName)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
			testCheckCompatibleVersion(t, featurePrivileges)
			testEnsureTestRoleExists(t, roleName)
		},
		Providers: testAccProviders,
		CheckDestroy: func() resource.TestCheckFunc {
			// there is nothing to check, just clean up the created role
			return func(s *terraform.State) error {
				testEnsureTestRoleDestroyed(t, roleName)
				return nil
			}
		}(),
		Steps: []resource.TestStep{
			{
				Config: configCreate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "name", roleName),
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "connection_limit", "10"),
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "bypass_row_level_security", "true"),
					withDBClient(t, func(client *Client) error {
						return checkConnLimit(client, roleName, 10)
					}),
					withDBClient(t, func(client *Client) error {
						return checkBypassRLS(client, roleName, true)
					}),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "name", roleName),
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "connection_limit", "100"),
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "bypass_row_level_security", "false"),
					resource.TestCheckResourceAttr("postgresql_role_attribute.test", "create_database", "true"),
					withDBClient(t, func(client *Client) error {
						return checkConnLimit(client, roleName, 100)
					}),
					withDBClient(t, func(client *Client) error {
						return checkBypassRLS(client, roleName, false)
					}),
					withDBClient(t, func(client *Client) error {
						return checkCreateDB(client, roleName, true)
					}),
				),
			},
		},
	})
}

func withDBClient(t *testing.T, f func(*Client) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testAccProvider.Meta().(*Client)
		if client == nil {
			t.Logf("Client is nil")
			t.FailNow()
		}
		if err := f(client); err != nil {
			return fmt.Errorf("Error: %s", err)
		}
		return nil
	}
}

func checkConnLimit(client *Client, roleName string, expectedConnLimit int) error {
	db, err := client.Connect()
	if err != nil {
		return fmt.Errorf("Error connecting to postgres: %s", err)
	}

	var connLimit int
	err = db.QueryRow("SELECT rolconnlimit FROM pg_catalog.pg_roles WHERE rolname = $1", roleName).Scan(&connLimit)
	if err != nil {
		return fmt.Errorf("Error querying role: %s", err)
	}

	if connLimit != expectedConnLimit {
		return fmt.Errorf("Expected connection limit to be %d, got %d", expectedConnLimit, connLimit)
	}

	return nil
}

func checkBypassRLS(client *Client, roleName string, expectedBypassRLS bool) error {
	db, err := client.Connect()
	if err != nil {
		return fmt.Errorf("Error connecting to postgres: %s", err)
	}

	var bypassRLS bool
	err = db.QueryRow("SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = $1", roleName).Scan(&bypassRLS)
	if err != nil {
		return fmt.Errorf("Error querying role: %s", err)
	}

	if bypassRLS != expectedBypassRLS {
		return fmt.Errorf("Expected bypass row level security to be %t, got %t", expectedBypassRLS, bypassRLS)
	}

	return nil
}

func checkCreateDB(client *Client, roleName string, expectedCreateDB bool) error {
	db, err := client.Connect()
	if err != nil {
		return fmt.Errorf("Error connecting to postgres: %s", err)
	}

	var createDB bool
	err = db.QueryRow("SELECT rolcreatedb FROM pg_catalog.pg_roles WHERE rolname = $1", roleName).Scan(&createDB)
	if err != nil {
		return fmt.Errorf("Error querying role: %s", err)
	}

	if createDB != expectedCreateDB {
		return fmt.Errorf("Expected create database to be %t, got %t", expectedCreateDB, createDB)
	}

	return nil
}
