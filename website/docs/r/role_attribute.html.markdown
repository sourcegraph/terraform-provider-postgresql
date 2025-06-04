---
layout: "postgresql"
page_title: "PostgreSQL: postgresql_role_attribute"
sidebar_current: "docs-postgresql-resource-role-attribute"
description: >-
  Creates and manages attributes of a role in a PostgreSQL database.
---

# postgresql_role_attribute

The `postgresql_role_attribute` resource creates and manages attributes of a role in a PostgreSQL database. Unlike the `postgresql_role` resource which manages the entire role in an authoritative manner, this resource allows managing specific attributes of a role without controlling the entire role definition. It is useful when the creation of role is managed by another provider, but they don't support managing specific attributes. Additionally, this resource does not remove the role attributes on destroy. 

~> **NOTE:** If you're already using `postgresql_role` to manage the role, you should not use `postgresql_role_attribute` to modify the role's attributes. This resource is intended for cases where the role is managed by another provider or when you need to modify specific attributes without affecting the entire role definition.

## Example Usage

```hcl
# Create a create with the Google terraform provider
resource "google_sql_user" "app_iam_service_account" {
  # Note: for Postgres only, GCP requires omitting the ".gserviceaccount.com" suffix
  # from the service account email due to length limits on database usernames.
  name     = trimsuffix(google_service_account.service_account.email, ".gserviceaccount.com")
  instance = google_sql_database_instance.main.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

// Manage the role attributes using the PostgreSQL provider
// that are impossible to manage with the Google provider
resource "postgresql_role_attribute" "app_iam_service_account_role_attrs" {
  name                      = postgresql_role.app_iam_service_account.name
  bypass_row_level_security = true
}
```

## Argument Reference

* `name` - (Required) The name of the role. This role must already exist.
* `bypass_row_level_security` - (Optional) Determine whether this role bypasses every row-level security (RLS) policy.
* `connection_limit` - (Optional) If this role can log in, this specifies how many concurrent connections the role can establish. `-1` (the default) means no limit.
* `create_database` - (Optional) Define whether this role is allowed to create databases.
* `create_role` - (Optional) Determine whether this role will be permitted to create new roles.
* `idle_in_transaction_session_timeout` - (Optional) Terminate any session with an open transaction that has been idle for longer than the specified duration in milliseconds.
* `inherit` - (Optional) Determine whether a role inherits the privileges of roles it is a member of.
* `login` - (Optional) Determine whether a role is allowed to log in.
* `password` - (Optional) Sets the role's password.
* `encrypted_password` - (Optional) Control whether the password is stored encrypted in the system catalogs. Default is `true`.
* `replication` - (Optional) Determine whether a role is allowed to initiate streaming replication or put the system in and out of backup mode.
* `superuser` - (Optional) Determine whether the new role is a superuser.
* `valid_until` - (Optional) Sets a date and time after which the role's password is no longer valid.
* `search_path` - (Optional) Sets the role's search path.
* `statement_timeout` - (Optional) Abort any statement that takes more than the specified number of milliseconds.
* `assume_role` - (Optional) Role to switch to at login.

## Import

PostgreSQL roles can be imported using the `name`, e.g.

```
$ terraform import postgresql_role_attribute.admin_attributes admin
```