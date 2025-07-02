## Active Directory Structure
```bash
# Active Directory Structure

# AD is a hierarchical, distributed directory service for Windows environments.
# Provides authentication, authorization, and centralized management.

# Key Components:
# - Forest: Top-level security boundary.
# - Domain: Logical grouping of objects (users, computers, etc.).
# - Child Domain: Subdomain under parent (e.g., dev.corp.local).
# - OU: Used to organize objects & apply GPOs(e.g, groups users computers..).

# AD Objects That Can Be Enumerated:
# - Users, Computers, Groups, OUs
# - GPOs, ACLs, Trusts, Password Policies

# Default access: Even low-privilege users can enumerate most AD objects.

# AD Structure Example:
# INLANEFREIGHT.LOCAL/
# ├── ADMIN.INLANEFREIGHT.LOCAL    (child domain)
# │   └── EMPLOYEES → USERS, GROUPS, COMPUTERS
# ├── CORP.INLANEFREIGHT.LOCAL
# └── DEV.INLANEFREIGHT.LOCAL

# Trusts:
# - Enable access between domains/forests.
# - Forest Trust: Created between root domains; bidirectional or one-way.
# - Child domains do NOT automatically trust other children in another forest.
#   → e.g., admin.dev.freightlogistics.local ❌ wh.corp.inlanefreight.local
#   → Requires explicit child-to-child trust.

# Security Risks:
# - Misconfigs in trusts or GPOs can lead to lateral movement & privilege escalation.
```
## Active Directory Terminology
```bash
# Active Directory Terminology

## Object
  # An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc.

## Attributes
  # Every object in Active Directory has attributes that define it (e.g., a computer object has hostname, DNS name, etc.). Each attribute has an LDAP name (e.g., displayName) used in LDAP queries for Full Name.

## Schema
  # it the blueprint of the enterprise environment, it defines what type/(class) of the object in AD dbs and their info,(e.g, users belong to "user" class), when object created : the process of creation it class instantiation and the created object called instance. 
  
## Domain
  # group of objects such as OUs groups computers, etc . a domain can operate independently of one another or can be connected via trusted relationshpis.

## Forest
  # it collection of one of multiple domains/(trees), Each Forest operate independently or can be connected via trusted relationships.

## Tree
  # it collection of sub/child domains begain with root domain, Each domain in tree share a boundary with the other domain.and there is trust between parent-child in a tree , all domains in tree share a standard Global Catalog contain all info about the object belong to the tree.GC is a feature that is enabled on a domain controller

## Container
  # Container objects hold other objects and have a defined place in the directory subtree hierarchy.

## Leaf
  # Leaf objects do not contain other objects and are found at the end of the subtree hierarchy. (e.g, users , priters, computers)

## Global Unique Identifier (GUID)
  # is unique value acrocss the enterprice, assigned to every object in AD and stored in "ObjectGUID" attribute of every object it used to identify objects.

## Security principals
  # in AD : are domain objects that manage access to other resources within the domian like Users. in no AD env the local user and groups used to controls the access the resource and managed by the SAM (system Account Manager)

## Security Identifier (SID)
  # used as unique indentifier for security principals or security group, every account, gorup process has it own SID,in AD it issued by domian controller. when user login the system creat token contain the user SID and the right they hvae granted and the SIDs for any Groups that the user is member of, This token check the right whenever the user perform an action on the pc. 

## Distinguished Name (DN)
  # the full path to an object in AD (e.g, cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local), it used search or access the object (there are another way like GUID)

## Relative Distinguished Name (RDN)
  # Just one part of the full DN. (e.g, in the DNs cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local) the RDN = cn=bjones

## sAMAccountName
  # The sAMAccountName is the user's logon name. Here it would just be bjones.

## userPrincipalName
  # another way to identify users in AD. This attribute consists of a prefix (the user account name) and a suffix (the domain name) in the format of bjones@inlanefreight.local.This attribute is not mandatory.

## FSMO (Flexible Single Master Operation )Roles
  # FSMO roles are typically set when there is many DCs created , There are 5 FSMO roles, 2 per forest (Schema Master, Domain Naming Master) and 3 per domain (RID Master, PDC Emulator, Infrastructure Master), assigned to Domain Controllers to ensure smooth AD operations and replication. the first DC can have all the roles and the new others DCs will only have the 3 (RID Master, PDC Emulator, Infrastructure Master)

## Global Catalog
  # GC is a feature that is enabled on a domain controller to Authenticate and Object search for any objects in ANY domain in the forest no only via the tree


## domain controller  
  # is a sever (machine) run the AD service 
  
# Read-Only Domain Controller (RODC) 
  # has a read-only Active Directory database, no cached no chnage puched.(eg. protect the SYSVOL from changing )

## Replication
  # Replication happens in AD when AD objects are updated and transferred from one Domain Controller to another in the forest.Replication ensures that changes are synchronized with all other DCs in a forest, helping to create a backup in case one domain controller fails.

## Service Principal Name (SPN)
  # uniquely identifies a service instance . eg : MSSQLSvc/sqlserver01.domain.local:1433, MSSQLSvc: serviece class, sqlserver01 is the server name run the sql service

## Group Policy Object (GPO)
  # are virtual collections of policy settings for the users and computer names within the domain or defined more granularly at the OU level.A GPO can contain local file system settings or Active Directory settings.

## Access Control List (ACL)
  # A list of access control entries (ACEs)
## Access Control Entries (ACEs)
  # each ACE in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.

## Discretionary Access Control List (DACL)
  # A specific type of ACL whose purpose is to **grant or deny** a trustee’s discretionary access rights to that object.

## System Access Control Lists (SACL)
  # Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

## Fully Qualified Domain Name (FQDN)
  # An FQDN is the complete name for a specific computer or host, [host name].[domain name].[tld] .can be used to locate hosts in an Active Directory without knowing the IP address

## Tombstone
  #  Tombstone is a deleted AD object marked with isDeleted=TRUE, and Deleted Objects is the container that temporarily holds these tombstoned objects during the tombstone lifetime.

## AD Recycle Bin
  #  restore a deleted object for a period of time

## SYSVOL
  # stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, tasks script.replicated to all DCs within the environment using File Replication Services (FRS) 

## AdminSDHolder
  # object it checks members of protected groups to ensure that the correct ACL is applied to them in scheduled "SDProp" proccess, so evern an attacker change the ACL to get right over the domain admin group, they right will be removed by the AdminSDHolder

## dsHeuristics 
  # The dsHeuristics attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings. One of these settings is to exclude built-in groups from the Protected Groups list. Groups in this list are protected from modification via the AdminSDHolder object. If a group is excluded via the dsHeuristics attribute, then any changes that affect it will not be reverted when the SDProp process runs.

## adminCount 
  # The adminCount attribute determines whether or not the SDProp process protects a user. If the value is set to 0 or not specified, the user is not protected. If the attribute value is set to 1, the user is protected. Attackers will often look for accounts with the adminCount attribute set to 1 to target in an internal environment. These are often privileged accounts and may lead to further access or full domain compromise.

## Active Directory Users and Computers (ADUC)
  # ADUC is a GUI console commonly used for managing users, groups, computers, and contacts in AD. Changes made in ADUC can be done via PowerShell as well.

## ADSI Edit
  # ADSI Edit is a GUI tool used to manage objects in AD. It provides access to far more than is available in ADUC

## sIDHistory
  # this attribute holds any SIDs that an object was assigned previously. It is usually used in migrations so a user can maintain the same level of access when migrated from one domain to another. This attribute can potentially be abused if set insecurely, allowing an attacker to gain prior elevated access that an account had before a migration if SID Filtering (or removing SIDs from another domain from a user's access token that could be used for elevated access) is not enabled.

## NTDS.DIT
  # The NTDS.DIT file can be considered the heart of Active Directory. It is stored on a Domain Controller at C:\Windows\NTDS\ and is a database that stores AD data such as information about user and group objects and passwords/hashs

## MSBROWSE
  # MSBROWSE is a legacy Windows network tag used to identify the Master Browser, which managed the list of shared resources (like files and printers) on old windows LANs. we could use nbtstat -A ip-address to search for the Master Browser. If we see MSBROWSE it means that's the Master Browser. Aditionally we could use nltest utility to query a Windows Master Browser for the names of the Domain Controllers.

```

##  Active Directory Objects
```bash
# Active Directory Objects
## AD objects is ANY resource present within an AD environment such as OUs, printers, users, domain controllers. 

## USERS
  # considered leaf objects, which means that they cannot contain any other objects within them
  # considered a security principal and has a SID and GUID 
  # attributes :display name, last login time, date of last password change, email address, account description, manager, address, and more
  # crucial target for attackers since gaining access to even a low privileged user can grant access to many objects and resources and allow for detailed enumeration of the entire domain (or forest).

## Contacts  
  # not actual AD users accounts, they cannot login .for external people like vendors
  # leaf objects, only GUID and No SID so they are NOT security principals

##  Printers
  # points to a printer accessible within the AD
  # leaf objects, only GUID and No SID so they are NOT security principals
  # attributes: printer's name, driver information, port number, etc.

## Computers
  # Any computer joined to AD (workstation or server)
  # Leaf object in AD + Security principal: has SID + GUID
  # Has a computer account (COMPUTERNAME$) with username/pass in AD
  # Computer account = low-priv AD user (like a standard domain user)
  # Can authenticate to AD, access resources, and enum AD
  # SYSTEM on domain machine → uses COMPUTERNAME$ to auth over network
  # So if I get SYSTEM → I can enum AD & access domain shares


## Shared Folders
  # points to a shared folder on the specific computer
  # only GUID , No SID and no security principals
  # have a permission access : can be access only to auth users (wish mean low AD user or computer account/(authority system)  could access it)
  # attributes:  name, location,security access

## Groups
  # container object: can contain Users, computers , other groups..
  # security principl : GUID + SID
  # manage access of the users and computers to securable objects 
  # Nested groups = a group inside another group instead of adding users directly you add a group as a member of another group.to save time , nested group can lead to a users obtaining unintended rights
  # attributes : name, description, membership..and more

## Organizational Units (OUs)
  # is a container that can use to store objects
  # Used to apply policies and delegate admin rights
  # Example: AD = OUs (HR,IT,Finance), User:ahmed 
    # we can apply admin rights for the user ahmed only on HR OU

## Domain
  # container contain objects such as users and computers..more
  # Every domain has its own database and its own policies for all objects inside it.

## Domain Controllers
  # the brains of an AD network
  # handle authentication requests 
  # controle access to resources in the domain

## Sites
  # in AD is a set of computers across one or more subnets connected using high-speed links. They are used to make replication across domain controllers run efficiently.

## Built-in
  # container that holds default groups in an AD domain. They are predefined when an AD domain is created.

```