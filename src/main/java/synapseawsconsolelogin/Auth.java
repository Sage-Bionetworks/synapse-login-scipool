
package synapseawsconsolelogin;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
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
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.model.Verifier;

import com.amazonaws.AmazonClientException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterResult;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;


public class Auth extends HttpServlet {
	private static Logger logger = Logger.getLogger("Auth");

	private static final String CLAIMS_TEMPLATE = "{\"team\":{\"values\":[\"%1$s\"]},%2$s}";
	private static final String CLAIM_TEMPLATE="\"%1$s\":{\"essential\":true}";
	private static final String TOKEN_URL = "https://repo-prod.prod.sagebase.org/auth/v1/oauth2/token";
	private static final String REDIRECT_URI = "/synapse";
	private static final String HEALTH_URI = "/health";
	private static final String AWS_CONSOLE_URL_TEMPLATE = "https://%1$s.console.aws.amazon.com/servicecatalog/home?region=%1$s#/products";
	private static final String AWS_SIGN_IN_URL = "https://signin.aws.amazon.com/federation";
	private static final String USER_CLAIMS_DEFAULT="userid";
	private static final String SIGNIN_TOKEN_URL_TEMPLATE = AWS_SIGN_IN_URL + 
            "?Action=getSigninToken&SessionDuration=%1$s&SessionType=json&Session=%2$s";
	static final String PROPERTIES_FILENAME_PARAMETER = "PROPERTIES_FILENAME";
	private static final int SESSION_TIMEOUT_SECONDS_DEFAULT = 43200;
	private static final String SSM_RESERVED_PREFIX = "ssm::";
		
	private Map<String,String> teamToRoleMap;
	private String sessionTimeoutSeconds;
	private String awsRegion;
	private Properties properties = null;
	private Properties ssmParameterCache = null;
	private String awsConsoleUrl;
	
	Map<String,String> getTeamToRoleMap() throws JSONException {
		String jsonString = getProperty("TEAM_TO_ROLE_ARN_MAP");
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

	public Auth() {
		initProperties();
		ssmParameterCache = new Properties();
		String sessionTimeoutSecondsString=getProperty("SESSION_TIMEOUT_SECONDS", false);
		if (sessionTimeoutSecondsString==null) {
			sessionTimeoutSeconds = ""+SESSION_TIMEOUT_SECONDS_DEFAULT;
		} else {
			sessionTimeoutSeconds = sessionTimeoutSecondsString;
		}
		teamToRoleMap = getTeamToRoleMap();
		awsRegion = getProperty("AWS_REGION");
		awsConsoleUrl = String.format(AWS_CONSOLE_URL_TEMPLATE, awsRegion);
	}
	
	public List<String> getClaimNames() {
		String userClaimString = getProperty("USER_CLAIMS", false);
		if (StringUtils.isEmpty(userClaimString)) userClaimString=USER_CLAIMS_DEFAULT;
		return Arrays.asList(userClaimString.split(","));
	}

	public String getAuthorizeUrl() {
		StringBuilder sb = new StringBuilder();
		boolean first=true;
		for (String claimName : getClaimNames()) {
			if (first) first=false; else sb.append(",");
			sb.append(String.format(CLAIM_TEMPLATE, claimName));
		}
		String claims = String.format(CLAIMS_TEMPLATE, StringUtils.join(teamToRoleMap.keySet(), "\",\""), sb.toString());
		return "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&"+
		"claims={\"id_token\":"+claims+",\"userinfo\":"+claims+"}";
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
		String result = getProperty("SYNAPSE_OAUTH_CLIENT_ID");
		logger.log(Level.WARNING, "SYNAPSE_OAUTH_CLIENT_ID="+result);
		return result;
	}
	
	private String getClientSecretSynapse() {
		String result =  getProperty("SYNAPSE_OAUTH_CLIENT_SECRET");
		return result;
	}

	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			resp.setContentType("text/plain");
			try (ServletOutputStream os=resp.getOutputStream()) {
				os.println("Error:");
				e.printStackTrace(new PrintStream(os));
			}
			resp.setStatus(500);
		}
	}
	
	// from https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html#STSConsoleLink_programJava
	String getConsoleLoginURL(HttpServletRequest req, Credentials federatedCredentials, HttpGetExecutor httpGetExecutor) throws IOException {

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
				sessionTimeoutSeconds, URLEncoder.encode(sessionJson,"UTF-8"));

		String returnContent = httpGetExecutor.executeHttpGet(getSigninTokenURL);

		String signinToken = new JSONObject(returnContent).getString("SigninToken");

		String signinTokenParameter = "&SigninToken=" + URLEncoder.encode(signinToken,"UTF-8");

		// The issuer parameter is optional, but recommended. Use it to direct users
		// to your sign-in page when their session expires.

		String issuerParameter = "&Issuer=" + URLEncoder.encode(issuerURL, "UTF-8");

		// Finally, present the completed URL for the AWS console session to the user
		String loginURL = AWS_SIGN_IN_URL + "?Action=login" +
				signinTokenParameter + issuerParameter +
				"&Destination=" + URLEncoder.encode(awsConsoleUrl,"UTF-8");
		
		return loginURL;
	}
	
	public static Jwt<Header,Claims> parseJWT(String token) {
		// Note, we don't check the signature
		String[] pieces = token.split("\\.");
		if (pieces.length!=3) throw new IllegalArgumentException("Expected three sections of the token but found "+pieces.length);
		String unsignedToken = pieces[0]+"."+pieces[1]+".";
		return Jwts.parser().parseClaimsJwt(unsignedToken);
	}
		
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws Exception {
		
		OAuth2Api.BasicOAuth2Service service = null;
		String uri = req.getRequestURI();
		if (uri.equals("/") || StringUtils.isEmpty(uri)) {
			// this is the initial redirect to go log in with Synapse
			String redirectBackUrl = getRedirectBackUrlSynapse(req);
			String redirectUrl = new OAuth2Api(getAuthorizeUrl(), TOKEN_URL).
					getAuthorizationUrl(new OAuthConfig(getClientIdSynapse(), null, redirectBackUrl, null, "openid", null));
			resp.setHeader("Location", redirectUrl);
			resp.setStatus(303);
		}	else if (uri.equals(REDIRECT_URI)) {
			// this is the second step, after logging in to Synapse
			service = (OAuth2Api.BasicOAuth2Service)(new OAuth2Api(getAuthorizeUrl(), TOKEN_URL)).
					createService(new OAuthConfig(getClientIdSynapse(), getClientSecretSynapse(), getRedirectBackUrlSynapse(req), null, null, null));
			String authorizationCode = req.getParameter("code");
			Token idToken = service.getIdToken(null, new Verifier(authorizationCode));
			
			// parse ID Token
			Jwt<Header,Claims> jwt = parseJWT(idToken.getToken());
			List<String> teamIds = jwt.getBody().get("team", List.class);
			
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

			StringBuilder awsSessionName = new StringBuilder();
			boolean first=true;
			for (String claimName : getClaimNames()) {
				String claimValue = jwt.getBody().get(claimName, String.class);
				if (StringUtils.isEmpty(claimValue)) continue;
				if (first) first=false; else awsSessionName.append(":");
				awsSessionName.append(claimValue);
			}

			// get STS token
			AssumeRoleWithWebIdentityRequest assumeRoleWithWebIdentityRequest = new AssumeRoleWithWebIdentityRequest();
			assumeRoleWithWebIdentityRequest.setWebIdentityToken(idToken.getToken());
			assumeRoleWithWebIdentityRequest.setRoleArn(roleArn);
			assumeRoleWithWebIdentityRequest.setRoleSessionName(awsSessionName.toString());
			AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
					.withRegion(Regions.fromName(awsRegion))
					.withCredentials(new AWSCredentialsProvider() {
						@Override
						public AWSCredentials getCredentials() {
							return new AWSCredentials() {
								@Override
								public String getAWSAccessKeyId() {
									return "dummyKeyId";
								}
								@Override
								public String getAWSSecretKey() {
									return "dummySecret";
								}};
						}
						@Override
						public void refresh() {}}).build();
			
			AssumeRoleWithWebIdentityResult assumeRoleWithWebIdentityResult = stsClient.assumeRoleWithWebIdentity(assumeRoleWithWebIdentityRequest);
			Credentials credentials = assumeRoleWithWebIdentityResult.getCredentials();
			// redirect to AWS login
			String redirectURL = getConsoleLoginURL(req, credentials, new HttpGetExecutor() {

				@Override
				public String executeHttpGet(String urlString) throws IOException {
					URL url = new URL(urlString);
					URLConnection conn = url.openConnection();
					BufferedReader bufferReader = new BufferedReader(
							new InputStreamReader(conn.getInputStream()));  
					return bufferReader.readLine();
				}});
			
			resp.setHeader("Location", redirectURL);
			resp.setStatus(302);
		}	else if (uri.equals(HEALTH_URI)) {
			resp.setStatus(200);
		} else {
			throw new RuntimeException("Unexpected URI "+req.getRequestURI());
		}
	}
	
	public void initProperties() {
		if (properties!=null) return;
		properties = new Properties();
		
		String propertyFileName = System.getenv(PROPERTIES_FILENAME_PARAMETER);
		if (StringUtils.isEmpty(propertyFileName)) {
			propertyFileName = System.getProperty(PROPERTIES_FILENAME_PARAMETER);
			
		}
		if (StringUtils.isEmpty(propertyFileName)) {
			propertyFileName = "global.properties";
			
		}
		
		InputStream is = null;
		try {
			is = Auth.class.getClassLoader().getResourceAsStream(propertyFileName);
			if (is!=null) properties.load(is);
		} catch (IOException e) {
			logger.log(Level.INFO, propertyFileName+" does not exist.");
		} finally {
			if (is!=null) try {
				is.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
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
				if (required) throw new RuntimeException("Cannot find value in SSM for parameter name"+ssmParameterName);
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

}
