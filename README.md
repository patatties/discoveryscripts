# discoveryscripts
discoveryscripts that i use in daily life. These scripts are used to get a quick overview over situations at customer spaces.

Lots of these scripts are White-box, and request via Active Directory for example. That means that a high level of privileges is required to run these normally.

# cheat sheet
I love a good cheat sheet, so here i go :)

#### run a command on a system using winrm and the local domain
Invoke-Command -ComputerName localhost {netstat -ano | select-string LISTEN | Select-String :139} | Format-Table -AutoSize

