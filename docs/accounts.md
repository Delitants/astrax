# Management accounts

Sign in with your username and password over HTTPS. The initial account is
`admin`; upgrading preserves its existing password. There is no default password.

Administrators can open **Users** to create accounts, change roles, disable
access, reset passwords, or delete accounts. New accounts default to Viewer.
At least one enabled Administrator must remain.

| Role | Access |
| --- | --- |
| Administrator | Full configuration, accounts, credentials and API management |
| Operator | Monitoring and start/stop/restart of existing streams |
| Viewer | Read-only monitoring |

Operators cannot change stream configuration, retune or restart DVB cards,
manage softcams, or restart the server. Credential-bearing URLs, configuration
and raw logs are restricted to administrators. Permissions are enforced by the
server, not just by hidden buttons.

Every user can change their own password under **My account**. Changing a
password, role or enabled status signs out the affected user's sessions; other
users stay signed in. Sessions also expire after 30 minutes idle or 12 hours
from sign-in. Use separate accounts rather than sharing the administrator login.
