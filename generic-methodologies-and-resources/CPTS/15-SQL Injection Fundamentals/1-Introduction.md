 Modern web apps rely on databases to store and retrieve content and user data; the application backend issues SQL queries in response to user requests.
 
- **SQL Injection (SQLi)** happens when attacker-controlled input is used to build SQL queries, allowing the attacker to change the intended query or run new queries.
- Attackers typically escape input limits (e.g., with `'` or `"`) and then use techniques like stacked queries or `UNION` to execute and retrieve malicious results.

- **Consequences** include theft of sensitive data (passwords, credit cards), bypassing authentication (login bypass), unauthorized access to admin functions, file reads/writes on the server, backdoors and full site compromise.
- **Root causes** are insecure coding (unsafe string concatenation of user input into SQL) and lax database/user privileges.

- **Prevention (high level)**: validate and sanitize inputs, use parameterized queries/prepared statements, limit database user privileges, and follow secure-coding best practices.