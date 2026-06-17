package default_credentials

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "default-credentials"
	ModuleName  = "Default Credentials"
	ModuleShort = "Tests for default or common credential pairs on login endpoints"
)

var (
	ModuleDesc = `**What it means:** A login endpoint accepts a well-known default credential pair (admin/admin, root/root, tomcat/tomcat) never changed after install, granting authenticated access.

**How it's exploited:** An attacker logs in with the same pair to take over the account, often gaining admin access. Confirmed only when a default pair yields a response different from the invalid-credential baseline that reproduces but not for random credentials; a bare session cookie or a redirect back to login is not enough.

**Fix:** Force a password change on all default accounts at first use, disable demo accounts, and enforce strong unique passwords.`

	ModuleConfirmation = "Confirmed when a known credential pair produces a response significantly different from the invalid-credential baseline, indicating successful authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"auth-bypass", "probe", "moderate"}
)
