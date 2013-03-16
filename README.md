CSRF packege
====

CSRF (XSRF) Token generation and validation for Go web app.

CSRF token generation and validation for cross server communication.

Usage:
``` 
  go get  github.com/postfix/csrf
```  
---

```go
  import (
     "github.com/postfix/csrf"
     "time"   
  )

  //Init
  csrf.Key = []byte("changme") // Secret hmac key
  csrf.Timeout = 24 * time.Hour // 1d expiration
  // Generate
  actionid := string("POST /form")
  sessionid :=string(usersession)
  csrftoken := csrf.newToken(actionid,sessionid)
  //Validate
  if !csrf.Valid(csrftoken,actionid,sessionid) {
      fmt.Println("Error: csrf token not valid")
  }
```
