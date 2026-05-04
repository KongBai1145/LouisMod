Set-ProcessUIAClaim -Force >$null 2>&1
Start-Process -FilePath "bcdedit" -ArgumentList "/set testsigning on" -Verb RunAs -Wait -WindowStyle Normal
