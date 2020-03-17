package dwdtoken

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"

	"cloud.google.com/go/compute/metadata"
	credentials "cloud.google.com/go/iam/credentials/apiv1"
	credentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1"
)

func AppEngineDWDTokenSource(ctx context.Context, sub string, scope ...string) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, gaeDwdSource{ctx: ctx, sub: sub, scopes: scope})
}

type gaeDwdSource struct {
	ctx    context.Context
	sub    string
	scopes []string
}

func gae_project() string {
	return os.Getenv("GOOGLE_CLOUD_PROJECT")
}

func (dwd gaeDwdSource) Token() (*oauth2.Token, error) {
	email, err := metadata.Get("instance/service-accounts/default/email")
	if err != nil {
		return nil, err
	}

	iat := time.Now()
	exp := iat.Add(time.Hour)
	cs := &jws.ClaimSet{
		Iss:   email,
		Sub:   dwd.sub,
		Scope: strings.Join(dwd.scopes, " "),
		Aud:   google.Endpoint.TokenURL,
		Iat:   iat.Unix(),
		Exp:   exp.Unix(),
	}
	hdr := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}
	signer := func(d []byte) ([]byte, error) {
		c, err := credentials.NewIamCredentialsClient(dwd.ctx)
		if err != nil {
			return nil, err
		}

		resp, err := c.SignBlob(dwd.ctx, &credentialspb.SignBlobRequest{
			Name:    fmt.Sprintf("projects/-/serviceAccounts/%s", email),
			Payload: d,
		})

		return resp.SignedBlob, err
	}
	msg, err := jws.EncodeWithSigner(hdr, cs, signer)
	if err != nil {
		return nil, fmt.Errorf("GAE DWD Access Token: could not encode JWT: %v", err)
	}

	postData := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {msg},
	}
	data, err := fullPost(dwd.ctx, google.Endpoint.TokenURL, postData)
	if err != nil {
		return nil, fmt.Errorf("GAE DWD Access Token: Failed Requesting Token: %s", err)
	}

	resp := &GoogleToken{}
	err = json.Unmarshal(data, resp)
	if err != nil {
		return nil, fmt.Errorf("GAE DWD Access Token: Failed Unmarshalling Token Response: %s", err)
	}

	if resp.AccessToken == "" {
		return nil, fmt.Errorf("GAE DWD Access Token: Invalid Response: %s", data)
	}

	return &oauth2.Token{AccessToken: resp.AccessToken, TokenType: "Bearer", Expiry: exp}, nil
}

type GoogleToken struct {
	AccessToken string `json:"access_token"`
}

func fullPost(ctx context.Context, url string, data url.Values) ([]byte, error) {
	buf := new(bytes.Buffer)

	client := http.Client{
		Timeout: time.Second,
	}

	response, err := client.PostForm(url, data)
	if err != nil {
		return []byte{}, fmt.Errorf("Error During Request: %s", err)
	}
	defer response.Body.Close()

	buf.ReadFrom(response.Body)

	return buf.Bytes(), nil
}
