# Windows 10 and Users (e-mail)

Windows is a multi-user environment.  This means multiple users can be defined to login to the computer, and multiple users can run programs on the computer, just not all using the same keyboard, mouse, and display.  Each user can have different permissions, most commonly separated into Administrators and Users.

The scenario lays out pretty clearly who are authorized and of the authorized users, who are administrators.  This makes it relatively easy for us to identify who should be able to login to the computer.

## Finding Who Has Access to the Computer

To find the local users that have access to the computer, you can go to `Control Panel->User Accounts->Remove user accounts`.  Although our goal is not to remove user accounts, this path in the UI will bring you to the *Manage Accounts* screen.

This screen is a good place that will allow you to see all of the users, and show you the type of account they have (administrator or user), along with letting you know if they have a password assigned.

If we recall back to the Passwords discussion, this is the place to know if you have to assigne a user a password.

With the list of authorized users and administrators that was presented in the scenario, you should check the following items:

- Is the user in the list?
- Do they match the role defined in the list?
- Do they have a password?

If any of those do not match, it is most likely something that you need to fix.

The one caution I have is that if an account is not in the list of authorized users, make sure that it does not fall into one of the other categories below before removing it.

## Service Accounts

There is a concept of accounts that are used to run different "services" on the computer.  Services are programs that run in the background to provide operations to the operating system, but will not interact with any users.  For some of these services to run, and have proper permissions assigned to them, they must have users created.

Before removing any users, you may have to search what the service name is and see if it is a valid service.  The removal of valid service accounts can severly hinder a system.

## Default Administrator

All Windows computer comes with a default administrator that has been creatively named `Administrator`.  When there is a default administrator account, the account tends to be targeted by malicious intent.

A common security practice (or should be common, but not always), is to rename the administrator account to something else, and then create a low-privilege user named `Administrator` and is disabled.  In this way, if a malicious person is trying to hack the administrators password using the name, they should get no where.
