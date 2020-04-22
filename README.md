# Overview
This app logs in to the AWS Console using Synapse as the OpenID Connect
(OIDC) identity provider

## Configurations
The app must be configured with five parameters which can be passed as
properties, environment variables, AWS Simple System Management (SSM) parameters,
or a properties file on the class loader search path called 
[global.properties](src/main/resources/global.properties)
like so:

```
SYNAPSE_OAUTH_CLIENT_ID=xxxxxx
SYNAPSE_OAUTH_CLIENT_SECRET=xxxxxx
TEAM_TO_ROLE_ARN_MAP=[{"teamId":"xxxxxx","roleArn":"arn:aws:iam::xxxxxx:role/ServiceCatalogEndusers"}, ...]
AWS_REGION=us-east-1
SESSION_TIMEOUT_SECONDS=43200
USER_CLAIMS=userid
```

The name of the properties file, `global.properties` can be overridden by setting an environment variable or 
system property called `PROPERTIES_FILENAME`.

In the case that a parameter is passed in multiple ways, priority is as follows:
- Environment variable
- System property
- Properties file entry
- SSM parameter

Note:  The intention is to use SSM to securely store the OAuth client secret.  Instructions on how to put a parameter into SSM can be found [here](https://docs.aws.amazon.com/cli/latest/reference/ssm/put-parameter.html).  To store the client secret, use `--name SYNAPSE_OAUTH_CLIENT_SECRET`, `--type SecureString` and set `--value` to the client secret.

### Team to role map
This defines the mapping between the synapse team and the AWS role. When
mapping team ID to AWS Role, this app' uses the first match it encounters,
iterating through the team/role list in the order given. 

### Claims
The `USER_CLAIMS` config is a comma separated list of claims from the list of
available claims, given here:
https://rest-docs.synapse.org/rest/org/sagebionetworks/repo/model/oauth/OIDCClaimName.html

For example: setting `USER_CLAIMS=userid,email` will display
`ServiceCatalogEndusers/1234567:joe.smith@gmail.com` in AWS. 

## Building the app
This is a java application which we build with standard [apache maven](https://maven.apache.org/what-is-maven.html)
tooling. AWS beanstalk requires files to be in a
[standard diredtory structure](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/java-tomcat-platform-directorystructure.html).

```buildoutcfg
mvn clean package
```

## Deployments
We deploy this application to an existing [AWS beanstalk](https://aws.amazon.com/elasticbeanstalk/)
container which is defined by cloudformation templates in our
[synapse-login-aws-infra](https://github.com/Sage-Bionetworks/synapse-login-aws-infra) repo.

We use the [AWS EB CLI](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3.html)
to deploy.

```
eb deploy synapse-login-scipooldev --profile my-aws --region us-east-1
```

## Continuous Integration
We have configured Travis CI to automatically build, test and deploy the application.

## Contributions
Contributions are welcome

## Development Workflow
This project has two branches `develop`, and `prod`.  When proposing changes to this project
the workflow is to create a PR against develop branch, merge it there then promote it to
prod branch.

step by step:
1. Propose PR to develop branch
2. Review and approve the PR then merge it to develop branch
3. CI/CD system builds, test, and deploys artifact from develop branch to AWS dev
environment in the org-sagebase-scipooldev AWS account
4. Manually verify application in dev environment
5. Promote to prod environment in org-sagebase-scipoolprod by merging the commit to the
prod branch
6. CI/CD system deploys to prod environment
7. Verify again in prod environment

## Issues
* https://sagebionetworks.jira.com/projects/SC

## Builds
* https://travis-ci.org/Sage-Bionetworks/synapse-login-scipoolprod
