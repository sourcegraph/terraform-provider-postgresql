package postgresql

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/lib/pq"
)

const (
	rolePgAuditLogAttr = "pgaudit_log"
)

func resourcePostgreSQLRoleAttribute() *schema.Resource {
	return &schema.Resource{
		Create: PGResourceFunc(resourcePostgreSQLRoleAttributeCreate),
		Read:   PGResourceFunc(resourcePostgreSQLRoleAttributeRead),
		Update: PGResourceFunc(resourcePostgreSQLRoleAttributeUpdate),
		Delete: PGResourceFunc(resourcePostgreSQLRoleAttributeDelete),
		Exists: PGResourceExistsFunc(resourcePostgreSQLRoleAttributeExists),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			roleNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role",
			},
			roleBypassRLSAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Determine whether a role bypasses every row-level security (RLS) policy",
			},
			roleConnLimitAttr: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "How many concurrent connections can be made with this role",
				ValidateFunc: validation.IntAtLeast(-1),
			},
			roleCreateDBAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Define a role's ability to create databases",
			},
			roleCreateRoleAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Determine whether this role will be permitted to create new roles",
			},
			roleIdleInTransactionSessionTimeoutAttr: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Terminate any session with an open transaction that has been idle for longer than the specified duration in milliseconds",
				ValidateFunc: validation.IntAtLeast(0),
			},
			roleInheritAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: `Determine whether a role "inherits" the privileges of roles it is a member of`,
			},
			roleLoginAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Determine whether a role is allowed to log in",
			},
			rolePasswordAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Sets the role's password",
			},
			roleEncryptedPassAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Control whether the password is stored encrypted in the system catalogs",
			},
			roleReplicationAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Determine whether a role is allowed to initiate streaming replication or put the system in and out of backup mode",
			},
			roleSuperuserAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: `Determine whether the new role is a "superuser"`,
			},
			roleValidUntilAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Sets a date and time after which the role's password is no longer valid",
			},
			roleSearchPathAttr: {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				MinItems:    0,
				Description: "Sets the role's search path",
			},
			roleStatementTimeoutAttr: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Abort any statement that takes more than the specified number of milliseconds",
				ValidateFunc: validation.IntAtLeast(0),
			},
			roleAssumeRoleAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Role to switch to at login",
			},
			rolePgAuditLogAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "pgAudit log settings for this role. Valid values: READ, WRITE, FUNCTION, ROLE, DDL, MISC, MISC_SET, ALL. Multiple values can be comma-separated (e.g., 'READ,WRITE')",
			},
		},
	}
}

func resourcePostgreSQLRoleAttributeCreate(db *DBConnection, d *schema.ResourceData) error {
	txn, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	roleName := d.Get(roleNameAttr).(string)

	// Check if role exists
	var exists bool
	err = txn.QueryRow("SELECT true FROM pg_catalog.pg_roles WHERE rolname=$1", roleName).Scan(&exists)
	switch {
	case err == sql.ErrNoRows:
		return fmt.Errorf("role %s does not exist", roleName)
	case err != nil:
		return fmt.Errorf("error checking role existence: %w", err)
	}

	// Set role attributes
	if err = setRoleAttributes(txn, db, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	d.SetId(roleName)

	return resourcePostgreSQLRoleAttributeReadImpl(db, d)
}

func resourcePostgreSQLRoleAttributeRead(db *DBConnection, d *schema.ResourceData) error {
	return resourcePostgreSQLRoleAttributeReadImpl(db, d)
}

func resourcePostgreSQLRoleAttributeReadImpl(db *DBConnection, d *schema.ResourceData) error {
	var roleSuperuser, roleInherit, roleCreateRole, roleCreateDB, roleCanLogin, roleReplication, roleBypassRLS bool
	var roleConnLimit int
	var roleName, roleValidUntil string
	var roleConfig pq.ByteaArray

	roleID := d.Id()

	columns := []string{
		"rolname",
		"rolsuper",
		"rolinherit",
		"rolcreaterole",
		"rolcreatedb",
		"rolcanlogin",
		"rolconnlimit",
		`COALESCE(rolvaliduntil::TEXT, 'infinity')`,
		"rolconfig",
	}

	values := []interface{}{
		&roleName,
		&roleSuperuser,
		&roleInherit,
		&roleCreateRole,
		&roleCreateDB,
		&roleCanLogin,
		&roleConnLimit,
		&roleValidUntil,
		&roleConfig,
	}

	if db.featureSupported(featureReplication) {
		columns = append(columns, "rolreplication")
		values = append(values, &roleReplication)
	}

	if db.featureSupported(featureRLS) {
		columns = append(columns, "rolbypassrls")
		values = append(values, &roleBypassRLS)
	}

	roleSQL := fmt.Sprintf(`SELECT %s FROM pg_catalog.pg_roles WHERE rolname=$1`,
		// select columns
		strings.Join(columns, ", "),
	)

	err := db.QueryRow(roleSQL, roleID).Scan(values...)

	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL role (%s) not found", roleID)
		d.SetId("")
		return nil
	case err != nil:
		return fmt.Errorf("Error reading role: %w", err)
	}

	d.Set(roleNameAttr, roleName)

	// Only set parameters in the state for attributes that were actually set in the config
	if _, ok := d.GetOk(roleBypassRLSAttr); ok {
		d.Set(roleBypassRLSAttr, roleBypassRLS)
	}
	if _, ok := d.GetOk(roleConnLimitAttr); ok {
		d.Set(roleConnLimitAttr, roleConnLimit)
	}
	if _, ok := d.GetOk(roleCreateDBAttr); ok {
		d.Set(roleCreateDBAttr, roleCreateDB)
	}
	if _, ok := d.GetOk(roleCreateRoleAttr); ok {
		d.Set(roleCreateRoleAttr, roleCreateRole)
	}
	if _, ok := d.GetOk(roleInheritAttr); ok {
		d.Set(roleInheritAttr, roleInherit)
	}
	if _, ok := d.GetOk(roleLoginAttr); ok {
		d.Set(roleLoginAttr, roleCanLogin)
	}
	if _, ok := d.GetOk(roleSuperuserAttr); ok {
		d.Set(roleSuperuserAttr, roleSuperuser)
	}
	if _, ok := d.GetOk(roleReplicationAttr); ok {
		d.Set(roleReplicationAttr, roleReplication)
	}
	if _, ok := d.GetOk(roleValidUntilAttr); ok {
		d.Set(roleValidUntilAttr, roleValidUntil)
	}
	if _, ok := d.GetOk(roleSearchPathAttr); ok {
		d.Set(roleSearchPathAttr, readSearchPath(roleConfig))
	}
	if _, ok := d.GetOk(roleAssumeRoleAttr); ok {
		d.Set(roleAssumeRoleAttr, readAssumeRole(roleConfig))
	}

	if _, ok := d.GetOk(roleStatementTimeoutAttr); ok {
		statementTimeout, err := readStatementTimeout(roleConfig)
		if err != nil {
			return err
		}
		d.Set(roleStatementTimeoutAttr, statementTimeout)
	}

	if _, ok := d.GetOk(roleIdleInTransactionSessionTimeoutAttr); ok {
		idleInTransactionSessionTimeout, err := readIdleInTransactionSessionTimeout(roleConfig)
		if err != nil {
			return err
		}
		d.Set(roleIdleInTransactionSessionTimeoutAttr, idleInTransactionSessionTimeout)
	}

	if _, ok := d.GetOk(rolePasswordAttr); ok {
		password, err := readRolePassword(db, d, roleCanLogin)
		if err != nil {
			return err
		}
		d.Set(rolePasswordAttr, password)
	}

	if _, ok := d.GetOk(rolePgAuditLogAttr); ok {
		d.Set(rolePgAuditLogAttr, readPgAuditLog(roleConfig))
	}

	return nil
}

func resourcePostgreSQLRoleAttributeUpdate(db *DBConnection, d *schema.ResourceData) error {
	txn, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	if err := setRoleAttributes(txn, db, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return resourcePostgreSQLRoleAttributeReadImpl(db, d)
}

func resourcePostgreSQLRoleAttributeDelete(db *DBConnection, d *schema.ResourceData) error {
	// No-op: we don't want to remove the role when this resource is destroyed
	// since this resource only manages specific attributes of the role.
	// It is hard to tell what the role's original attributes were, hence
	// destroy is a no-op and we just forget about it.
	d.SetId("")
	return nil
}

func resourcePostgreSQLRoleAttributeExists(db *DBConnection, d *schema.ResourceData) (bool, error) {
	var roleName string
	err := db.QueryRow("SELECT rolname FROM pg_catalog.pg_roles WHERE rolname=$1", d.Id()).Scan(&roleName)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func setRoleAttributes(txn *sql.Tx, db *DBConnection, d *schema.ResourceData) error {

	// Set each attribute if it's in the config
	if d.HasChange(roleBypassRLSAttr) {
		if err := setRoleBypassRLS(db, txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleConnLimitAttr) {
		if err := setRoleConnLimit(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleCreateDBAttr) {
		if err := setRoleCreateDB(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleCreateRoleAttr) {
		if err := setRoleCreateRole(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleInheritAttr) {
		if err := setRoleInherit(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleLoginAttr) {
		if err := setRoleLogin(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(rolePasswordAttr) {
		if err := setRolePassword(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleReplicationAttr) {
		if err := setRoleReplication(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleSuperuserAttr) {
		if err := setRoleSuperuser(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleValidUntilAttr) {
		if err := setRoleValidUntil(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleSearchPathAttr) {
		if err := alterSearchPath(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleStatementTimeoutAttr) {
		if err := setStatementTimeout(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleIdleInTransactionSessionTimeoutAttr) {
		if err := setIdleInTransactionSessionTimeout(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(roleAssumeRoleAttr) {
		if err := setAssumeRole(txn, d); err != nil {
			return err
		}
	}

	if d.HasChange(rolePgAuditLogAttr) {
		if err := setPgAuditLog(txn, d); err != nil {
			return err
		}
	}

	return nil
}

// readPgAuditLog searches for a pgaudit.log entry in the rolconfig array.
// In case no such value is present, it returns empty string.
func readPgAuditLog(roleConfig pq.ByteaArray) string {
	pgAuditLogAttr := "pgaudit.log"
	for _, v := range roleConfig {
		config := string(v)
		if strings.HasPrefix(config, pgAuditLogAttr) {
			return strings.TrimPrefix(config, pgAuditLogAttr+"=")
		}
	}
	return ""
}

// setPgAuditLog sets the pgaudit.log parameter for a role
func setPgAuditLog(txn *sql.Tx, d *schema.ResourceData) error {
	roleName := d.Get(roleNameAttr).(string)
	pgAuditLog := d.Get(rolePgAuditLogAttr).(string)
	
	var sql string
	if pgAuditLog == "" {
		// Reset to default if empty
		sql = fmt.Sprintf("ALTER ROLE %s RESET pgaudit.log", pq.QuoteIdentifier(roleName))
	} else {
		sql = fmt.Sprintf("ALTER ROLE %s SET pgaudit.log = '%s'", pq.QuoteIdentifier(roleName), pqQuoteLiteral(pgAuditLog))
	}
	
	if _, err := txn.Exec(sql); err != nil {
		return fmt.Errorf("could not set pgaudit.log for role %s: %w", roleName, err)
	}
	return nil
}
