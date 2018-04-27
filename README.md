OAuth2 Token Source for DWD (Domain Wide Delegation) on Google App Engine Standard Environment

An example, using DWD & impersonation on the default App Engine Service Account:

```go
package main

import (
	"html/template"
	"net/http"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/user"
	"google.golang.org/appengine/urlfetch"
	"google.golang.org/api/admin/directory/v1"
	"github.com/iamacarpet/go-gae-dwd-tokensource"

	"private/model"
)

type AuthCheckMiddleware struct {
	User         *user.User
	UserThumbURL string
	LogoutURL    string
}

func (c *AuthCheckMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := appengine.NewContext(r)

	if u := user.Current(ctx); u == nil {
		// If no user logged in, redirect to login.
		url, _ := user.LoginURL(ctx, r.URL.Path)
		http.Redirect(rw, r, url, 302)
		return
	} else if ! c.isUserAllowed(ctx, u.Email) {
		log.Errorf(ctx, "Access Denied for email %s to %s", u.Email, r.URL.Path)

        // Example of rendering a 403 page.
		errorTemplate := template.Must(template.ParseFiles("views/403.html"))
		c.User = u
		c.UserThumbURL, _ = model.GetAnonymousUserThumbnail(ctx, u.Email)
        c.LogoutURL, _ = user.LogoutURL(ctx, r.URL.Path)

		rw.WriteHeader(403)
        errorTemplate.Execute(rw, c)

		return
	}

	next(rw, r)
}

func (c *AuthCheckMiddleware) isUserAllowed(ctx context.Context, email string) bool {
	return c.groupMembershipCheck(ctx, "my-group@gsuite-domain.com", email)
}

func (c *AuthCheckMiddleware) groupMembershipCheck(ctx context.Context, group string, email string) bool {
	transport := &oauth2.Transport{
		Source: dwdtoken.AppEngineDWDTokenSource(ctx, "admin-user@gsuite-domain.com", admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupMemberReadonlyScope),
		Base:   &urlfetch.Transport{Context: ctx},
	}
	client := &http.Client{Transport: transport}

	srv, err := admin.New(client)
	if err != nil {
		log.Errorf(ctx, "AuthCheckMiddleware.groupMembershipCheck: API Init: %s", err)
		return false
	}

	result, err := srv.Members.HasMember(group, email).Do()
	if err != nil {
		log.Errorf(ctx, "AuthCheckMiddleware.groupMembershipCheck: API Membership Check (%s of %s): %s", email, group, err)
		return false
	}

	return result.IsMember
}

```

To make this work, you need to edit the default service account and tick "Enable DWD", then follow [this](https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account) guide to add it to your G Suite domain.