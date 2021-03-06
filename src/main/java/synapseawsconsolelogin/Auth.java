
package synapseawsconsolelogin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.sagebionetworks.client.SynapseClient;
import org.sagebionetworks.client.SynapseClientImpl;
import org.sagebionetworks.client.exceptions.SynapseBadRequestException;
import org.sagebionetworks.client.exceptions.SynapseException;
import org.sagebionetworks.client.exceptions.SynapseForbiddenException;
import org.sagebionetworks.client.exceptions.SynapseNotFoundException;
import org.sagebionetworks.client.exceptions.SynapseServerException;
import org.sagebionetworks.client.exceptions.SynapseServiceUnavailable;
import org.sagebionetworks.client.exceptions.SynapseUnauthorizedException;
import org.sagebionetworks.repo.model.auth.AccessTokenGenerationRequest;
import org.sagebionetworks.repo.model.oauth.OAuthScope;
import org.sagebionetworks.repo.model.oauth.OIDCClaimsRequestDetails;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Verifier;

import com.amazonaws.AmazonClientException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.Tag;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterResult;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.lang.Collections;


public class Auth extends HttpServlet {
	private static Logger logger = Logger.getLogger("Auth");

	private static final String TEAM_CLAIM_NAME = "team";

	// templates for constructing the 'claims' part of the OIDC authorization request
	private static final String CLAIM_TEMPLATE="\"%1$s\":{\"essential\":true}";
	private static final String CLAIM_TEMPLATE_WITH_VALUES="\"%1$s\":{\"values\":[\"%2$s\"]}";
	
	private static final String SYNAPSE_ENDPOINT = "https://repo-prod.prod.sagebase.org/auth/v1";
	private static final String TOKEN_URL = SYNAPSE_ENDPOINT+"/oauth2/token";

	// we need 'openid' scope to get user claims/info and we need 'authorize' scope to create
	// a personal access token
	private static final List<OAuthScope> OAUTH_SCOPES = 
			Collections.arrayToList(new OAuthScope[] {OAuthScope.openid, OAuthScope.authorize});
	private static final String SPACE_SEPARATED_SCOPES;
	
	static {
		StringBuilder sb = new StringBuilder();
		for (OAuthScope scope : OAUTH_SCOPES) {
			sb.append(scope+" ");
		}
		SPACE_SEPARATED_SCOPES = sb.toString();
	}
	
	/*
	 * The default endpoint is the empty string or null, which 
	 * logs the user in to Service Catalog.
	 * The following are the supported alternate endpoints.
	 */
	private static final String STS_TOKEN_URI = "/ststoken"; // return STS token for the role indicated by the TEAM_TO_ROLE_ARN_MAP
	private static final String ACCESS_TOKEN_URI = "/accesstoken"; // return the OIDC access token returned by Synapse
	private static final String PERSONAL_ACCESS_TOKEN_URI = "/personalaccesstoken"; // create and return a personal access token for Synapse
	private static final String ID_TOKEN_URI = "/idtoken"; // return the OIDC ID token returned by Synapse

	/*
	 * This is the endpoint that Synapse redirects back to after logging the user in.
	 */
	private static final String REDIRECT_URI = "/synapse";
	
	/*
	 * This is the URI that AWS uses to check the system's health
	 */
	private static final String HEALTH_URI = "/health";
	
	/*
	 * This is the URI that returns the application's version
	 */
	public static final String ABOUT_URI = "/about";
	
	
	/*
	 * This is the URI that returns the 'sector identifier' information.  
	 * For details, see https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
	 */
	public static final String SECTOR_IDENTIFIER_URI  = "/redirect_uris.json";

	private static final String STATE = "state";
	private static final String LOCATION = "Location";
	private static final String UTF8 = "utf-8";

	private static final String AWS_CONSOLE_URL_TEMPLATE = "https://%1$s.console.aws.amazon.com/servicecatalog/home?region=%1$s#/products";
	private static final String AWS_SIGN_IN_URL = "https://signin.aws.amazon.com/federation";
	private static final String SESSION_NAME_CLAIMS_PROPERTY_NAME = "SESSION_NAME_CLAIMS";
	private static final String USER_ID_CLAIM_NAME="userid";
	private static final String SESSION_CLAIM_NAMES_DEFAULT=USER_ID_CLAIM_NAME;
	private static final String SESSION_TAG_CLAIMS_PROPERTY_NAME = "SESSION_TAG_CLAIMS";
	private static final String REDIRECT_URIS_PROPERTY_NAME = "REDIRECT_URIS";
	private static final String SESSION_TAG_CLAIMS_DEFAULT = USER_ID_CLAIM_NAME;
	private static final String SIGNIN_TOKEN_URL_TEMPLATE = AWS_SIGN_IN_URL + 
            "?Action=getSigninToken&SessionDuration=%1$s&SessionType=json&Session=%2$s";
	static final String PROPERTIES_FILENAME_PARAMETER = "PROPERTIES_FILENAME";
	static final String TEAM_TO_ROLE_ARN_MAP_PARAMETER = "TEAM_TO_ROLE_ARN_MAP";
	static final String SESSION_TIMEOUT_SECONDS_PARAMETER = "SESSION_TIMEOUT_SECONDS";
	static final String AWS_REGION_PARAMETER = "AWS_REGION";
	static final String SYNAPSE_OAUTH_CLIENT_ID_PARAMETER = "SYNAPSE_OAUTH_CLIENT_ID";
	static final String SYNAPSE_OAUTH_CLIENT_SECRET_PARAMETER = "SYNAPSE_OAUTH_CLIENT_SECRET";
	private static final int SESSION_TIMEOUT_SECONDS_DEFAULT = 43200;
	private static final String TAG_PREFIX = "synapse-";
	private static final String SSM_RESERVED_PREFIX = "ssm::";

	public static final String GIT_PROPERTIES_FILENAME = "git.properties";
	public static final String GIT_COMMIT_ID_DESCRIBE_KEY = "git.commit.id.describe";
	public static final String GIT_COMMIT_TIME_KEY = "git.commit.time";
	
	private static final String NONCE_TAG_NAME = "nonce";
	
	private static final String ISO_8601_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
	
	private static final String ERROR_HTML_HEADER = "<html><head/><body>\n<h3>An error has occurred:</h3>";
	
	private static final String ERROR_HTML_FOOTER = "</body></html>";
	
	private static final String BEARER_PREFIX = "Bearer ";
	
	private static final String PERSONAL_ACCESS_TOKEN_NAME = "AWS CLI access to %s";

	/*
	 * File name for the AWS config file containing the downloaded STS token
	 */
	private static final String STS_TOKEN_FILE_NAME = "ststoken.json";

	/*
	 * File name for the downloaded OIDC (ID or access) token
	 */
	private static final String OIDC_TOKEN_FILE_NAME = "synapse_oidc_token";

	private Map<String,String> teamToRoleMap;
	private String sessionTimeoutSeconds;
	private Properties properties = null;
	private Properties ssmParameterCache = null;
	private String awsConsoleUrl;
	private String appVersion = null;
	private AWSSecurityTokenService stsClient = null;
	private HttpGetExecutor httpGetExecutor	= null;
	private TokenRetriever tokenRetriever = null;
	private JWTClaimsExtractor jwtClaimsExtractor = null;
	private SynapseClient synapseClient = null;
	
	Map<String,String> getTeamToRoleMap() throws JSONException {
		String jsonString = getProperty(TEAM_TO_ROLE_ARN_MAP_PARAMETER);
		JSONArray array;
		try {
			array = new JSONArray(jsonString);
		} catch (JSONException e) {
			throw new JSONException("Error parsing "+jsonString, e);
		}
		Map<String,String> result = new LinkedHashMap<String,String>();
		for (Iterator<Object> iterator=array.iterator(); iterator.hasNext();) {
			JSONObject entry = (JSONObject)iterator.next();
			result.put(entry.getString("teamId"), entry.getString("roleArn"));
		}
		return result;
	}

	private void init(AWSSecurityTokenService stsClient, 
			HttpGetExecutor httpGetExecutor, 
			TokenRetriever tokenRetriever,
			JWTClaimsExtractor jwtClaimsExtractor,
			SynapseClient synapseClient) {
		this.stsClient = stsClient;
		this.httpGetExecutor = httpGetExecutor;
		this.tokenRetriever = tokenRetriever;
		this.jwtClaimsExtractor = jwtClaimsExtractor;
		this.synapseClient = synapseClient;
		
		this.appVersion = initAppVersion();

		String sessionTimeoutSecondsString=getProperty(SESSION_TIMEOUT_SECONDS_PARAMETER, false);
		if (sessionTimeoutSecondsString==null) {
			sessionTimeoutSeconds = ""+SESSION_TIMEOUT_SECONDS_DEFAULT;
		} else {
			sessionTimeoutSeconds = sessionTimeoutSecondsString;
		}
		teamToRoleMap = getTeamToRoleMap();
		String awsRegion = getProperty(AWS_REGION_PARAMETER);
		awsConsoleUrl = String.format(AWS_CONSOLE_URL_TEMPLATE, awsRegion);
	}
	
	/*
	 * For testing
	 */
	public Auth(AWSSecurityTokenService stsClient, 
			HttpGetExecutor httpGetExecutor, 
			TokenRetriever tokenRetriever,
			JWTClaimsExtractor jwtClaimsExtractor,
			SynapseClient synapseClient) {
		initProperties();
		init(stsClient, httpGetExecutor, tokenRetriever, jwtClaimsExtractor, synapseClient);
	}
		
	public Auth() {
		initProperties();
		String awsRegion = getProperty(AWS_REGION_PARAMETER);
		AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
				.withRegion(Regions.fromName(awsRegion)).build();
		
		HttpGetExecutor httpExecutor = new HttpGetExecutor() {
			@Override
			public String executeHttpGet(String urlString, String accessToken) throws IOException {
				URL url = new URL(urlString);
				HttpURLConnection conn = (HttpURLConnection)url.openConnection();
				if (StringUtils.isNotEmpty(accessToken)) {
					conn.setRequestProperty("Authorization", BEARER_PREFIX+accessToken);
				}
				int status = conn.getResponseCode();
				String message = conn.getResponseMessage();
				if (status>=400) {
					throw new IOException(message);
				}
				BufferedReader bufferReader = new BufferedReader(
						new InputStreamReader(conn.getInputStream()));  
				return bufferReader.readLine();
			}
		};
		
		TokenRetriever tokenRetriever = new TokenRetriever() {
			@Override
			public IdAndAccessToken getTokens(String redirectUrl, String authorizationCode) {
				OAuth2Api.BasicOAuth2Service service = (OAuth2Api.BasicOAuth2Service)(new OAuth2Api(null, TOKEN_URL)).
						createService(new OAuthConfig(getClientIdSynapse(), getClientSecretSynapse(), redirectUrl, null, null, null));
				return service.getIdAndAccessTokens(null, new Verifier(authorizationCode));
			}
			
		};
		
		JWTClaimsExtractor jwtClaimsExtractor = new JWTClaimsExtractor() {
			@Override
			public Map<String,Object> extractClaims(String jwtString) {
				Jwt<Header,Claims> jwt = parseJWT(jwtString);
				return jwt.getBody();
			}
		};
		
		SynapseClient synapseClient = new SynapseClientImpl();

		init(stsClient, httpExecutor, tokenRetriever, jwtClaimsExtractor, synapseClient);
	}

	
	public List<String> getCommaSeparatedPropertyAsList(String propertyName, String defaultValue) {
		String propertyValue = getProperty(propertyName, false);
		if (StringUtils.isEmpty(propertyValue)) propertyValue=defaultValue;
		return Arrays.asList(propertyValue.split(","));
	}

	public List<String> getSessionClaimNames() {
		return getCommaSeparatedPropertyAsList(SESSION_NAME_CLAIMS_PROPERTY_NAME, SESSION_CLAIM_NAMES_DEFAULT);
	}

	public List<String> getTagClaimNames() {
		return getCommaSeparatedPropertyAsList(SESSION_TAG_CLAIMS_PROPERTY_NAME, SESSION_TAG_CLAIMS_DEFAULT);
	}

	public List<String> getRedirectURIs(String defaultRedirectURI) {
		return getCommaSeparatedPropertyAsList(REDIRECT_URIS_PROPERTY_NAME, defaultRedirectURI);
	}
	
	/*
	 * Get 'claims' map to be used both (1) in the initial OAuth flow that logs in to Synapse,
	 * and (2) when creating the scope for the personal access token.
	 */
	private Map<String, OIDCClaimsRequestDetails> getUserInfoClaims() {
		Set<String> allClaims = new TreeSet<String>(getSessionClaimNames());
		allClaims.addAll(getTagClaimNames());
		Map<String, OIDCClaimsRequestDetails> result = new LinkedHashMap<String, OIDCClaimsRequestDetails>();
		for (String claimName : allClaims) {
			OIDCClaimsRequestDetails details = new OIDCClaimsRequestDetails();
			details.setEssential(true);
			if (TEAM_CLAIM_NAME.equals(claimName)) {
				details.setValues(new ArrayList<String>(teamToRoleMap.keySet()));
			}
			result.put(claimName, details);
		}
		return result;
	}

	/**
	 * 
	 * @param state the state to be carried through authentication and returned to this 
	 * server when Synapse is done authenticating the user.  If null then no 'state' request
	 * parameter will be included in the request
	 * @return the URL that the browser should be redirect to in order to authenticate with Synapse
	 */
	public String getAuthorizeUrl(String state) {
		StringBuilder sb = new StringBuilder("{");
		boolean first=true;
		List<String> teams = null;
		for (Map.Entry<String,OIDCClaimsRequestDetails> entry : getUserInfoClaims().entrySet()) {
			String claimName = entry.getKey();
			if (first) first=false; else sb.append(",");
			if (Collections.isEmpty(entry.getValue().getValues())) {
				sb.append(String.format(CLAIM_TEMPLATE, claimName));				
			} else {
				teams = entry.getValue().getValues();
				sb.append(String.format(CLAIM_TEMPLATE_WITH_VALUES, claimName, StringUtils.join(teams, "\",\"")));
			}
		}
		sb.append("}");
		String claims = sb.toString();
		String result = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&"+
				"claims={\"id_token\":"+claims+",\"userinfo\":"+claims+"}";
		if (StringUtils.isNotEmpty(state)) {
			result += "&"+STATE+"="+state;
		}
		return result;
	}
	
	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		resp.setContentType("text/plain");
		try (ServletOutputStream os=resp.getOutputStream()) {
			os.println("Not found.");
		}
		resp.setStatus(404);
	}

	private static String getThisEndpoint(HttpServletRequest req) throws MalformedURLException {
		String requestUrl = req.getRequestURL().toString();
		return requestUrl.substring(0, requestUrl.length()-req.getRequestURI().length());
	}
	
	private static String getRedirectBackUrlSynapse(HttpServletRequest req) throws MalformedURLException {
		return getThisEndpoint(req)+REDIRECT_URI;
	}
		
	private String getClientIdSynapse() {
		String result = getProperty(SYNAPSE_OAUTH_CLIENT_ID_PARAMETER);
		logger.log(Level.WARNING, SYNAPSE_OAUTH_CLIENT_ID_PARAMETER+"="+result);
		return result;
	}
	
	private String getClientSecretSynapse() {
		String result =  getProperty(SYNAPSE_OAUTH_CLIENT_SECRET_PARAMETER);
		return result;
	}
	
	static int synapseExceptionStatus(SynapseServerException e) {
		if (e instanceof SynapseBadRequestException) return 400;
		if (e instanceof SynapseForbiddenException) return 403;
		if (e instanceof SynapseNotFoundException) return 404;
		if (e instanceof SynapseServiceUnavailable) return 503;
		if (e instanceof SynapseUnauthorizedException) return 401;
		// there are other exception types to map but these are the most common
		// and we don't expect others. For the rest we'll just return 500.
		return 500;
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			handleException(e, resp);
		}
	}
	
	/*
	 * If we get an error when making a request to Synapse (e.g. a 403 for using
	 * an invalid token) then we pass this along.  Otherwise we just return a 500
	 * status.
	 */
	private static void handleException(Exception e, HttpServletResponse resp) throws IOException {
		if (e instanceof SynapseServerException) {
			resp.setStatus(synapseExceptionStatus((SynapseServerException)e));
			resp.setContentType("text/html");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println(ERROR_HTML_HEADER);
				os.println(e.getMessage());
				os.println(ERROR_HTML_FOOTER);
			}
		} else {
			logger.log(Level.SEVERE, e.getMessage(), e);
			resp.setStatus(500);
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println(ERROR_HTML_HEADER);
				e.printStackTrace(new PrintStream(os));
				os.println(ERROR_HTML_FOOTER);
			}
		}
	}

	// from https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html#STSConsoleLink_programJava
	String getConsoleLoginURL(HttpServletRequest req, Credentials federatedCredentials) throws IOException {

		String issuerURL = getThisEndpoint(req);

		// The issuer parameter specifies your internal sign-in
		// page, for example https://mysignin.internal.mycompany.com/.
		// The console parameter specifies the URL to the destination console of the
		// AWS Management Console. 
		// The signin parameter is the URL to send the request to.

		// Create the sign-in token using temporary credentials,
		// including the access key ID,  secret access key, and security token.
		String sessionJson = String.format(
		  "{\"%1$s\":\"%2$s\",\"%3$s\":\"%4$s\",\"%5$s\":\"%6$s\"}",
		  "sessionId", federatedCredentials.getAccessKeyId(),
		  "sessionKey", federatedCredentials.getSecretAccessKey(),
		  "sessionToken", federatedCredentials.getSessionToken());
		              
		// Construct the sign-in request with the request sign-in token action, a
		// specified console session duration, and the JSON document with temporary 
		// credentials as parameters.

		String getSigninTokenURL = String.format(SIGNIN_TOKEN_URL_TEMPLATE, 
				sessionTimeoutSeconds, URLEncoder.encode(sessionJson,UTF8));

		String returnContent = this.httpGetExecutor.executeHttpGet(getSigninTokenURL, null);

		String signinToken = new JSONObject(returnContent).getString("SigninToken");

		String signinTokenParameter = "&SigninToken=" + URLEncoder.encode(signinToken,UTF8);

		// The issuer parameter is optional, but recommended. Use it to direct users
		// to your sign-in page when their session expires.

		String issuerParameter = "&Issuer=" + URLEncoder.encode(issuerURL, UTF8);

		// Finally, present the completed URL for the AWS console session to the user
		String loginURL = AWS_SIGN_IN_URL + "?Action=login" +
				signinTokenParameter + issuerParameter +
				"&Destination=" + URLEncoder.encode(awsConsoleUrl, UTF8);
		
		return loginURL;
	}
	
	public static Jwt<Header,Claims> parseJWT(String token) {
		// Note, we don't check the signature
		String[] pieces = token.split("\\.");
		if (pieces.length!=3) throw new IllegalArgumentException("Expected three sections of the token but found "+pieces.length);
		String unsignedToken = pieces[0]+"."+pieces[1]+".";
		return Jwts.parser().parseClaimsJwt(unsignedToken);
	}
	
	// tag values must adhere to the regex: [\p{L}\p{Z}\p{N}_.:/=+\-@]* as per:
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#tag-restrictions
	public static String sanitizeTagValue(String tagValue) {
		return tagValue.replaceAll("[^\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]", " ");
	}
	
	public AssumeRoleRequest createAssumeRoleRequest(Map<String,Object> claims, String roleArn, String selectedTeam) {
		// here we collect all the user information to be added to the session
		Map<String,String> sessionTags = new HashMap<String,String>();
		
		for (String claimName: getTagClaimNames()) {
			Object claimValue = claims.get(claimName);
			if (TEAM_CLAIM_NAME.equals(claimName)) {
				// for this special claim name we put the selectedTeam rather than the claimValue, which is a list of teams
				sessionTags.put(TAG_PREFIX+claimName, selectedTeam);
			} else {
				if (claimValue!=null) {
					sessionTags.put(TAG_PREFIX+claimName, claimValue.toString());
				}
			}
		}
		
		// AWS has a bug in which, for certain combinations of tags, the redirect
		// to the console login results in an error.  See issue SC-178.  The fix 
		// is to ensure no particular combination of tags ever occurs more than once.
		// We accomplish this by adding a tag which is a random UUID.
		sessionTags.put(TAG_PREFIX+NONCE_TAG_NAME, UUID.randomUUID().toString());
		
		StringBuilder stringBuilder = new StringBuilder();
		boolean first=true;
		for (String claimName : getSessionClaimNames()) {
			String claimValue = (String)claims.get(claimName);
			if (StringUtils.isEmpty(claimValue)) continue;
			if (first) first=false; else stringBuilder.append(":");
			stringBuilder.append(claimValue);
		}
		String awsSessionName = stringBuilder.toString();
		
		// get STS token
		AssumeRoleRequest assumeRoleRequest = new AssumeRoleRequest();
		assumeRoleRequest.setRoleArn(roleArn);
		assumeRoleRequest.setRoleSessionName(awsSessionName);
		Collection<Tag> tags = new ArrayList<Tag>();
		for (String tagName: sessionTags.keySet()) {
			tags.add(new Tag().withKey(tagName).withValue(sanitizeTagValue(sessionTags.get(tagName))));				
		}
		assumeRoleRequest.setTags(tags);
		return assumeRoleRequest;
	}
	
	/**
	 * Determines whether the URI is one of the entrypoints to this application
	 * @param uri The URI (omitting the scheme, host and optional port)
	 * @return true if and only if the uri is one of the expected entrypoints
	 */
	static boolean isOAuthEntrypointUri(String uri) {
		return "/".equals(uri) || // note: The default entrypoint is the empty string
				StringUtils.isEmpty(uri) ||
				STS_TOKEN_URI.equals(uri) ||
				ID_TOKEN_URI.equals(uri) ||
				ACCESS_TOKEN_URI.equals(uri) ||
				PERSONAL_ACCESS_TOKEN_URI.equals(uri);
	}
	
	/**
	 * Maps the entrypoint URI to one of an enumeration of requests
	 * (redirect to Service Catalog, return an STS file, return a token, etc.)
	 * 
	 * @param uri the entrypoint URI
	 * @return the mapped ENUM
	 */
	static RequestType getRequestTypeFromUri(String uri) {
		if (StringUtils.isEmpty(uri) || "/".equals(uri)) {
			return RequestType.SC_CONSOLE;
		}
		if (STS_TOKEN_URI.equals(uri)) {
			return RequestType.STS_TOKEN;
		}
		if (ID_TOKEN_URI.equals(uri)) {
			return RequestType.ID_TOKEN;
		}
		if (ACCESS_TOKEN_URI.equals(uri)) {
			return RequestType.ACCESS_TOKEN;
		}
		if (PERSONAL_ACCESS_TOKEN_URI.equals(uri)) {
			return RequestType.PERSONAL_ACCESS_TOKEN;
		}
		throw new IllegalArgumentException("Unrecognized uri: "+uri);
	}
	
	/**
	 * Construct the HTTP redirect response that sends the browser to the Service Catalog console
	 * @param claims
	 * @param roleArn
	 * @param selectedTeam
	 * @param req
	 * @param resp
	 * @throws IOException
	 */
	void redirectToSCConsole(Map<String,Object> claims, String roleArn, String selectedTeam, HttpServletRequest req, HttpServletResponse resp) throws IOException {
		AssumeRoleRequest assumeRoleRequest = createAssumeRoleRequest(claims, roleArn, selectedTeam);
		
		AssumeRoleResult assumeRoleResult = stsClient.assumeRole(assumeRoleRequest);
		Credentials credentials = assumeRoleResult.getCredentials();
		// redirect to AWS login
		String redirectURL = getConsoleLoginURL(req, credentials);
		
		resp.setHeader(LOCATION, redirectURL);
		resp.setStatus(303);		
	}
	
	String formatDateAsIso8601(Date date) {
		DateFormat dateFormat = new SimpleDateFormat(ISO_8601_DATE_FORMAT);
		TimeZone tz = TimeZone.getTimeZone("UTC");
		dateFormat.setTimeZone(tz);
		return dateFormat.format(date);
	}

	/**
	 * Create the HTTP response to download a file containing the STS token
	 * which will allow the bearer to assume the end-user role. The file is
	 * in the format of an AWS CLI config file.
	 * 
	 * @param claims
	 * @param roleArn
	 * @param selectedTeam
	 * @param resp
	 * @throws IOException
	 */
	void returnStsToken(Map<String,Object> claims, String roleArn, String selectedTeam, HttpServletResponse resp) throws IOException {
		AssumeRoleRequest assumeRoleRequest = createAssumeRoleRequest(claims, roleArn, selectedTeam);
		
		AssumeRoleResult assumeRoleResult = stsClient.assumeRole(assumeRoleRequest);
		Credentials credentials = assumeRoleResult.getCredentials();
		Map<String,Object> sts = new HashMap<String,Object>();
		sts.put("AccessKeyId", credentials.getAccessKeyId());
		sts.put("SecretAccessKey", credentials.getSecretAccessKey());
		sts.put("SessionToken", credentials.getSessionToken());
		sts.put("Expiration", formatDateAsIso8601(credentials.getExpiration()));
		sts.put("Version", 1);

		writeFileToResponse(createSerializedJSON(sts), STS_TOKEN_FILE_NAME, resp);
	}
	
	/**
	 * Create serialized JSON for the given map of key/value pairs
	 * @param content
	 * @return
	 */
	public static String createSerializedJSON(Map<String,Object> content) {
		JSONObject o = new JSONObject();
		for (Map.Entry<String,Object> entry : content.entrySet()) {
			o.put(entry.getKey(), entry.getValue());
		}
		return o.toString();
	}
	
	/**
	 * Create the HTTP response for downloading a file
	 *
	 * @param content the file content
	 * @param filename the file name
	 * @param resp the HTTP response to write the result to
	 * @throws IOException
	 */
	public static void writeFileToResponse(String content, String filename, HttpServletResponse resp) throws IOException {
		resp.setStatus(200);
		resp.setContentType("application/force-download");
		resp.setCharacterEncoding(UTF8);
		resp.setHeader("Content-Transfer-Encoding", "binary");
		resp.setHeader("Cache-Control", "no-store, no-cache");
		resp.setHeader("Content-Disposition","attachment; filename=\""+filename+"\"");
		byte[] bytes = content.getBytes(UTF8);
		resp.setContentLength(bytes.length);
		try (ServletOutputStream os = resp.getOutputStream()) {
			os.write(bytes);
			os.flush();
		}
	}

	/**
	 * Extract the bearer authorization token from an HTTP request
	 * @param req
	 * @return the authorization token, or null if none is present
	 */
	static String getBearerAuthorizationToken(HttpServletRequest req) {
		String authHeader = req.getHeader("Authorization");
		if (StringUtils.isEmpty(authHeader)) {
			return null;
		}
		if (authHeader.toLowerCase().startsWith(BEARER_PREFIX.toLowerCase())) {
			return authHeader.substring(BEARER_PREFIX.length());
		}
		return null;
	}
		
	/**
	 * Create the HTTP response that writes a token to a file
	 * @param token
	 * @param resp
	 * @throws IOException
	 */
	void returnOidcToken(String token, HttpServletResponse resp) throws IOException {
		writeFileToResponse(token, OIDC_TOKEN_FILE_NAME, resp);
	}
	
	String getPersonalAccessToken(String accessToken, String stackName) throws SynapseException {
		synapseClient.setBearerAuthorizationToken(accessToken);
		AccessTokenGenerationRequest request = new AccessTokenGenerationRequest();
		request.setName(String.format(PERSONAL_ACCESS_TOKEN_NAME, stackName));
		request.setScope(OAUTH_SCOPES);
		request.setUserInfoClaims(getUserInfoClaims());
		return synapseClient.createPersonalAccessToken(request);
	}
	
	private void returnToken(RequestType requestType,  
			String accessToken,
			String idToken,
			Map<String,Object> idTokenClaims,
			HttpServletRequest req, 
			HttpServletResponse resp) throws IOException, SynapseException {
		// parse ID Token
		List<String> teamIds = (List<String>)idTokenClaims.get(TEAM_CLAIM_NAME);
		
		String selectedTeam = null;
		String roleArn = null;
		for (String teamId : teamToRoleMap.keySet()) {
			if (teamIds.contains(teamId)) {
				selectedTeam = teamId;
				roleArn = teamToRoleMap.get(teamId);
				break;
			}
		}

		if (roleArn==null) {
			resp.setContentType("text/html");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println("<html><head/><body>");
				os.println("<h3>To proceed you must be a member of one of these Synapse teams:</h3>");
				os.println("<ul>");
				for (String teamId : teamToRoleMap.keySet()) {
					os.println(String.format("<li><a href=\"https://www.synapse.org/#!Team:%1$s\">https://www.synapse.org/#!Team:%1$s</a></li>", teamId));
				}
				os.println("</ul>");
				os.println("</body></html>");
			}
			resp.setStatus(200);
			return;
		}
		
		// we take different actions for different services
		switch(requestType) {
		case SC_CONSOLE:
			redirectToSCConsole(idTokenClaims, roleArn, selectedTeam, req, resp);
			break;
		case STS_TOKEN:
			returnStsToken(idTokenClaims, roleArn, selectedTeam, resp);
			break;
		case ID_TOKEN:
			// creates file for use here: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html#cli-configure-role-oidc
			returnOidcToken(idToken, resp);
			break;
		case ACCESS_TOKEN:
			returnOidcToken(accessToken, resp);
			break;
		case PERSONAL_ACCESS_TOKEN:
			String pat = getPersonalAccessToken(accessToken, getThisEndpoint(req));
			returnOidcToken(pat, resp);
			break;
		default:
			throw new IllegalStateException("Unrecognized request type: "+requestType);
		}
	}
	
	private Map<String,Object> getUserInfo(String bearerToken) throws SynapseException {
		this.synapseClient.setBearerAuthorizationToken(bearerToken);
		JSONObject userInfo = synapseClient.getUserInfoAsJSON();
		return userInfo.toMap();
	}
	
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws Exception {
		
		String uri = req.getRequestURI();
		if (isOAuthEntrypointUri(uri)) {
			String bearerAuthorizationToken = getBearerAuthorizationToken(req);
			if (STS_TOKEN_URI.equals(uri) && StringUtils.isNotEmpty(bearerAuthorizationToken)) {
				// Get user info from the userinfo endpoint
				Map<String,Object> userInfoClaims = getUserInfo(bearerAuthorizationToken);
				// now return the STS token for the given user
				returnToken(RequestType.STS_TOKEN, bearerAuthorizationToken, null, userInfoClaims, req, resp);
			} else {
				// this is the initial redirect to go log in with Synapse
				String redirectBackUrl = getRedirectBackUrlSynapse(req);
				String state = getRequestTypeFromUri(uri).name();
				String redirectUrl = new OAuth2Api(getAuthorizeUrl(state), TOKEN_URL).
						getAuthorizationUrl(new OAuthConfig(getClientIdSynapse(), null, redirectBackUrl, null, SPACE_SEPARATED_SCOPES, null));
				resp.setHeader(LOCATION, redirectUrl);
				resp.setStatus(303);
			}
		} else if (REDIRECT_URI.equals(uri)) {
			// this is the second step, after logging in to Synapse
			RequestType requestType = RequestType.valueOf(req.getParameter(STATE));
			String authorizationCode = req.getParameter("code");
			IdAndAccessToken tokens =  this.tokenRetriever.getTokens(getRedirectBackUrlSynapse(req), authorizationCode);
			
			returnToken(requestType, 
					tokens.getAccessToken().getToken(),
					tokens.getIdToken().getToken(),
					jwtClaimsExtractor.extractClaims(tokens.getIdToken().getToken()),
					req, 
					resp);
			
		} else if (HEALTH_URI.equals(uri)) {
			resp.setStatus(200);
		} else if (ABOUT_URI.equals(uri)) {
			// Currently returns version
			resp.setContentType("application/json");
			resp.setCharacterEncoding(UTF8);
			resp.setStatus(200);
			JSONObject o = new JSONObject();
			o.put("version", appVersion);
			PrintWriter out = resp.getWriter();
			out.print(o.toString());
			out.flush();
		} else if (SECTOR_IDENTIFIER_URI.equals(uri)) {
			// returns a JSONArray containing all the redirect URIs under the sector identifier
			resp.setContentType("application/json");
			resp.setCharacterEncoding(UTF8);
			resp.setStatus(200);
			JSONArray o = new JSONArray();
			for (String s : getRedirectURIs(getRedirectBackUrlSynapse(req))) {
				o.put(s.trim());
			}
			PrintWriter out = resp.getWriter();
			out.print(o.toString());
			out.flush();
		} else { // we redirect unrecognized URIs back to the main login URL
			resp.setHeader(LOCATION, getThisEndpoint(req));
			resp.setStatus(303);
		}
	}
	
	public void initProperties() {
		if (properties!=null) return;

		String propertyFileName = System.getenv(PROPERTIES_FILENAME_PARAMETER);
		if (StringUtils.isEmpty(propertyFileName)) {
			propertyFileName = System.getProperty(PROPERTIES_FILENAME_PARAMETER);
			
		}
		if (StringUtils.isEmpty(propertyFileName)) {
			propertyFileName = "global.properties";
		}
		this.properties = loadProperties(propertyFileName);
		
		this.ssmParameterCache = new Properties();
	}

	private Properties loadProperties(String propertyFileName) {
		Properties props = new Properties();
		InputStream is = null;
		try {
			is = Auth.class.getClassLoader().getResourceAsStream(propertyFileName);
			if (is!=null) props.load(is);
		} catch (IOException e) {
			logger.log(Level.INFO, propertyFileName+" does not exist.");
		} finally {
			if (is!=null) try {
				is.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return props;
	}

	public String getProperty(String key) {
		return getProperty(key, true);
	}
	
	private static boolean missing(String s) {
		return StringUtils.isEmpty(s) || "null".equals(s);
	}

	public String getProperty(String key, boolean required) {
		if (missing(key)) {
			throw new IllegalArgumentException("property name is required");
		}
		String result=null;
		{
			result = System.getenv(key);
		}
		if (missing(result)) {
			result = System.getProperty(key);
		}
		if (missing(result)) {
			result = properties.getProperty(key);
		}
		if (missing(result)) {
			if (required) throw new RuntimeException("Cannot find value for "+key);
			return result;
		}
		// we have a value but it might be a pointer to SSM
		if (result.startsWith(SSM_RESERVED_PREFIX)) {
			String ssmParameterName = result.substring(SSM_RESERVED_PREFIX.length());
			// look up is expensive, so first check the cache
			result = ssmParameterCache.getProperty(ssmParameterName);
			if (missing(result)) {
				result = getSSMParameter(ssmParameterName);
				if (!missing(result)) {
					ssmParameterCache.setProperty(ssmParameterName, result);
				}
			}
			if (missing(result)) {
				if (required) throw new RuntimeException("Cannot find value in SSM for parameter name: "+ssmParameterName);
			}
		}
		return result;
	}
	
	private String getSSMParameter(String name) {
		if (name.length()<1) {
			throw new IllegalArgumentException("SSM parameter name cannot be empty.");
		}
		try {
			DefaultAWSCredentialsProviderChain.getInstance().getCredentials();
		} catch (SdkClientException e) {
			return null;
		}
		AWSSimpleSystemsManagement ssmClient = AWSSimpleSystemsManagementClientBuilder.defaultClient();
		GetParameterRequest getParameterRequest = new GetParameterRequest();
		getParameterRequest.setName(name);
		getParameterRequest.setWithDecryption(true);
		try {
			GetParameterResult getParameterResult = ssmClient.getParameter(getParameterRequest);
			return getParameterResult.getParameter().getValue();
		} catch (AmazonClientException e) {
			return null;
		}
	}

	public String initAppVersion() {
		Properties gitProps = loadProperties(GIT_PROPERTIES_FILENAME);
		if (! (gitProps.containsKey(GIT_COMMIT_TIME_KEY) && gitProps.containsKey(GIT_COMMIT_ID_DESCRIBE_KEY))) {
			throw new RuntimeException("Could not find Git properties in git.properties file!");
		}
		String version = String.format("%1$s-%2$s", gitProps.getProperty(GIT_COMMIT_TIME_KEY), gitProps.getProperty(GIT_COMMIT_ID_DESCRIBE_KEY));
		return version;
	}

	public String getAppVersion() {
		return appVersion;
	}

}
