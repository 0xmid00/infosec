## 1- Intro to Databases

Web apps use **databases** to store data like user info, posts, and files. These databases rely on **SQL (Structured Query Language)** to manage and retrieve data.  
Older **file-based systems** were slow, leading to the use of **Database Management Systems (DBMS)** for better performance and control.
#### Database Management Systems

A **DBMS** lets users and apps **create, manage, and secure** databases. It can be **Relational (RDBMS)**, **NoSQL**, or **Key/Value-based**, and is widely used in finance, education, and tech.

**Main features:**

| **Feature**     | **Description**                   |
| --------------- | --------------------------------- |
| **Concurrency** | Handles multiple users safely.    |
| **Consistency** | Keeps data valid and accurate.    |
| **Security**    | Controls access with permissions. |
| **Reliability** | Supports backups and recovery.    |
| **SQL**         | Simplifies data management.       |
#### Architecture

Databases work in layers:
![[Pasted image 20251029155711.png]]
- **Tier I (Client):** User interface (e.g., website or app).
- **Tier II (Server):** Processes user requests and talks to the database.
- **Tier III (DBMS):** Executes SQL operations like add, read, or update.

Large systems usually separate the **server** and **database** for better performance.


---
## 2- Types of Databases
Databases, in general, are categorized into `Relational Databases` and `Non-Relational Databases`. Only Relational Databases utilize SQL, while Non-Relational databases utilize a variety of methods for communications.
#### Relational Databases

- Use **tables (rows & columns)** and a **schema** to define data structure.
- Tables are linked by **keys** (e.g., `id`, `user_id`) so you can join related data without duplication.
- Good for structured data and predictable relationships — fast and reliable for many use cases.
- Common RDBMS: **MySQL, PostgreSQL, Oracle, SQL Server**.
- Simple example:
    - `users` table: `id, username, first_name, last_name`
    - `posts` table: `id, user_id, date, content`
    - Link `posts.user_id` → `users.id` to get author info for each post.
#### Non-relational Databases

- **NoSQL**(Non-relational Databases): no fixed tables or schemas; flexible storage models suited to unstructured or rapidly changing data.
- Main models: **Key-Value, Document, Wide-Column, Graph**.
- Highly scalable and flexible — great when data shape varies or speed at scale matters.
- Common NoSQL example: **MongoDB**.
- Key-Value example (JSON):
```json
{
  "100001": {"date":"01-01-2021","content":"Welcome to this web application."},
  "100002": {"date":"02-01-2021","content":"This is the first post."}
}
```
>Non-relational Databases have a different method for injection, known as NoSQL injections. SQL injections are completely different than NoSQL injections. NoSQL injections will be covered in a later module.