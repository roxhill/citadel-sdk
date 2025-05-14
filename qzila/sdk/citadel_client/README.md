# Citadel Client SDK

In order to resolve/revoke sessions you need to use Client SDK. Below is a simple example of how to instantiate the client with minimal config.

Once you have set up the client you can call any method on this client. Below is an example of resolving the session based on authentication cookies.

```go
package main

import (
  "encoding/json"
  "fmt"

  citadel "github.com/everlutionsk/go/qzila/sdk/citadel_client"
)

var client citadel.Client

func init() {
  // Set up the client
  client := citadel.NewClient(&citadel.ClientConfig{
    BaseURL:      "<URL of your Citadel instance>",
    ClientSecret: "<provided by Citadel tech team>",
  })
}

func main() {
  // Resolve session based on the "Cookie" header.
  response, err := client.SessionResolveBearer(&citadel.SessionResolveRequest{
    CookieHeader: "CSIDl=1; __Host-CSID=abc123",
  })

  if err != nil {
    // You can check the error against a broad selection of possible errors returned
    // by Citadel, for example:
    if errors.Is(err, citadel.NotFoundError) {
      fmt.Println("User session not found")
      os.Exit(1)
    }
    fmt.Printf("Unknown error: %s\n", err)
    os.Exit(1)
  }

  // If the request was successful, you can access the response data.
  // Check if the response is valid (meaning both session and session token are valid):
  fmt.Printf("Is response valid: %t\n", response.IsValid())

  if !response.IsValid() {
    // Check if user session is valid:
    fmt.Printf("Is user session valid: %t\n", response.Session().IsValid())
    // Check if session token is valid:
    fmt.Printf("Is session token valid: %t\n", response.SessionToken().IsValid())
  }

  // Access user's persistent data:
  if persistentData, ok := response.PersistentData(); ok {
    if data, ok := persistentData.Data(); ok {
      b, _ := json.MarshalIndent(v, "", "  ")
      fmt.Println("User data:")
      fmt.Println(string(b))
    }
  }
}
```
