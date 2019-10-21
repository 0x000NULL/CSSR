# Access Control

## Users

* Check that all users are authorized for access to the system.
    * Remove non-authorized users.
    * Keep files in for forensic analysis (or recovery)
    * *Caution* Do not remove service accounts.
* Check local users with admnistrator permissions are authorized administrators.
    * If not authorized, change user type to local user.
* Check authorized admnistrators are listed with administrator permissions.
    * If not, Change user type to local administrator.
* Check that all acounts have passwords assigned.
    * Create a password for accounts with out passwords.
    * For competition, Write down account name and password assigned.
* Check that the administrator account has been renamed. (Windows)
    * `Administrator` account does not have administrative permissions.
    * Another account is listed as built-in with administrative permissions.


## Passwords

* Check that password requirements are enforced to mininum recommendation.
    * Mininum length:  10 characters or more.
    * Maximum age:  90 days or less.
    * Mininum age:  1 day or more.
    * Password history:  10 passwords or more.
    * *Caution* Do not set rules to values that may lock the accounts out.
* Check that account lockouts are enforced.
    * Threshold:  5 bad passwords or less.
    * Duration:  15 minutes or more.
