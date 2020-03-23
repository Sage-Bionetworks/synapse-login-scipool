This app logs in to the AWS Console using Synapse as the OpenID Connect (OIDC) identity provider


Must be configured with five parameters which can be passed as properties, environment variables, or 
a properties file on the class loader search path called `global.properties` like so:

```
SYNAPSE_OAUTH_CLIENT_ID=xxxxxx
SYNAPSE_OAUTH_CLIENT_SECRET=xxxxxx
TEAM_TO_ROLE_ARN_MAP=[{"teamId":"xxxxxx","roleArn":"arn:aws:iam::xxxxxx:role/ServiceCatalogEndusers"}, ...]
AWS_REGION=us-east-1
SESSION_TIMEOUT_SECONDS=43200
```
Note: When mapping team ID to AWS Role, this app' uses the first match it encounters,
iterating through the team/role list in the order given.  



