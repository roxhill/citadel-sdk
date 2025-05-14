# Citadel Admin SDK

In order to manage users you need to use Admin SDK. Below is the simple example of how to instantiate the client with minimal config.

Once you have set up the client you can call any method on this client. Below is the example of getting the user info based on user id.

```go
package main

import (
  "fmt"
  "os"
  citadel "github.com/everlutionsk/go/qzila/sdk/citadel_admin"
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
  // Fetch user by ID.
  user, err := client.GetUser(&citadel.GetUserRequest{
    UserID: "<someUserID>",
  })

  if err != nil {
    // You can check the error against a broad selection of possible errors returned
    // by Citadel, for example:
    if errors.Is(err, citadel.ErrNotFound) {
      fmt.Println("User not found")
      os.Exit(1)
    }

    // Handle unknown errors.
    fmt.Printf("Unexpected error: %s\n", err)
    os.Exit(1)
  }

  // Now you can access user data.
  fmt.Printf("User:\n\n")
  fmt.Printf("%+v\n", user)
}
```
