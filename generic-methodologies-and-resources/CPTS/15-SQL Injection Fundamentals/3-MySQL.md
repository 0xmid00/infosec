## 1- Intro to MySQL

This section introduces **MySQL**, one of the most common relational databases used to explain **SQL Injection**. You’ll learn the basics of SQL syntax and MySQL commands used to create and manage databases.

#### Structured Query Language (SQL)

**SQL** is the language used to manage relational databases. While syntax may vary slightly between systems, all follow the **ISO SQL standard**.  
With SQL, you can:

- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users
#### Command Line

You can access MySQL using the `mysql` command-line tool:

```bash
mysql -u root -p
```

Avoid typing the password directly (`-p<password>`) since it may appear in logs.  
**To connect to a remote host:**
```bash
mysql -u root -h <host> -P 3306 -p
```

Default port: **3306**.  
Use `SHOW GRANTS` to view user privileges.
#### Creating a Database

Once logged in, create and view databases:

```sql
CREATE DATABASE users;
SHOW DATABASES;
USE users;
```

SQL commands are **not case-sensitive**, but database names are.
#### Tables

Data is stored in **tables** (rows and columns).  
Each column has a **data type** like `INT`, `VARCHAR`(character), or `DATETIME`.

Example:
```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
);
```

List tables and view their structure:

```sql
SHOW TABLES;
-- list the table structure with its fields and data types.
DESCRIBE logins;
```
##### Table Properties
You can add useful constraints and defaults:
```sql
CREATE TABLE logins (
  id INT NOT NULL AUTO_INCREMENT,        -- auto increase
  username VARCHAR(100) UNIQUE NOT NULL, -- no duplicates
  password VARCHAR(100) NOT NULL,
  date_of_joining DATETIME DEFAULT NOW(),-- current time
  PRIMARY KEY (id)                       -- unique identifier
);
```


---

## 2- SQL Statements 

Now that we understand how to use the `mysql` utility and create databases and tables, let us look at some of the essential SQL statements and their uses.
#### INSERT Statement

Add rows to a table.
```sql
INSERT INTO logins(username, password) VALUES('admin','p@ss');
-- multiple:
INSERT INTO logins(username, password) VALUES('a','x'),('b','y');
```
#### SELECT Statement

Retrieve data.
```sql
SELECT * FROM logins;                 -- all columns
SELECT COUNT(*) FROM table_name       --- count the record in the table
SELECT username, password FROM logins;-- specific columns
```
#### DROP Statement

Permanently remove a table or database.
```sql
DROP TABLE logins;
```
#### ALTER Statement

Change table structure (add/rename/modify/drop columns).
```sql
ALTER TABLE logins ADD age INT;                                       -- add column
ALTER TABLE logins RENAME COLUMN age TO years;                        -- rename column
ALTER TABLE logins MODIFY years DATE;                                 -- change datatype
ALTER TABLE logins DROP years;                                        -- delete column
```
#### UPDATE Statement

Modify existing rows.
```sql
UPDATE logins SET password='new_pass' WHERE id>1;                     -- update with condition
```


---

## 3- Query Results
This section shows how to control query output: sorting, limiting, and filtering.
#### Sorting Results

Use `ORDER BY` to sort rows (default = ascending).
```sql
SELECT * FROM logins ORDER BY password;
SELECT * FROM logins ORDER BY password DESC;   -- descending
SELECT * FROM logins ORDER BY password DESC, id ASC; -- multi-column
```
#### LIMIT results
`LIMIT` restricts how many rows are returned; add an offset if needed.
```sql
SELECT * FROM logins LIMIT 2;      -- first 2 rows
SELECT * FROM logins LIMIT 1, 2;   -- start at offset 1, return 2 rows
```
(Offsets start at 0.)
#### WHERE Clause

Filter rows with `WHERE` and conditions.
```sql
SELECT * FROM logins WHERE id > 1;
SELECT * FROM logins WHERE username = 'admin';
```
Strings/dates use quotes (`""`); numbers do not.
#### LIKE Clause

Pattern matching with `LIKE` using `%` (any chars) and `_` (one char).
```sql
SELECT * FROM logins WHERE username LIKE 'admin%'; -- starts with "admin"
SELECT * FROM logins WHERE username LIKE '___';    -- exactly 3 chars

# compaine search filters (AND operator)
select * from employees where first_name LIKE 'Bar%' AND hire_date = '1990-01-01';
```


---
## 4- SQL Operators
SQL supports logical operators (`AND`, `OR`, `NOT`) to combine multiple conditions in a query.
#### AND Operator

Returns `true` only if **both conditions** are true.
```sql
SELECT 1 = 1 AND 'test' = 'test';  -- true
SELECT 1 = 1 AND 'test' = 'abc';   -- false
```
#### OR Operator

Returns `true` if **at least one** condition is true.
```sql
SELECT 1 = 1 OR 'test' = 'abc';  -- true
SELECT 1 = 2 OR 'test' = 'abc';  -- false
```
#### NOT Operator

Negates a condition (`true` → `false`, `false` → `true`).
```sql
SELECT NOT 1 = 1;  -- false
SELECT NOT 1 = 2;  -- true
```
#### Symbol Operators

- `AND` → `&&`
- `OR` → `||`
- `NOT` → `!`
```sql
SELECT 1 = 1 && 'test' = 'abc';  -- false
SELECT 1 = 1 || 'test' = 'abc';  -- true
SELECT 1 != 1;                   -- false
```
#### Using Operators in Queries

```sql
SELECT * FROM logins WHERE username != 'john';
SELECT * FROM logins WHERE username != 'john' AND id > 1;
```
#### Operator Precedence

Operations are evaluated in this order:
1. `/`, `*`, `%`
2. `+`, `-`
3. `=`, `>`, `<`, `!=`, `LIKE`
4. `NOT`
5. `AND`
6. `OR`
Example:
```sql
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
-- Evaluates subtraction first → id > 1

# WHERE the employee number >  10000 OR title does NOT contain 'engineer'
select * from titles where emp_no > 10000 || title NOT LIKE '%engineer%'
```
