package synapseawsconsolelogin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.scribe.model.Token;

import com.amazonaws.AmazonClientException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.securitytoken.model.Tag;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.model.ParameterType;
import com.amazonaws.services.simplesystemsmanagement.model.PutParameterRequest;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;


@RunWith(MockitoJUnitRunner.class)
public class AuthTest {
	
	private static final String TEST_PROPERTY_NAME = "testPropertyName";
	
	@Mock
	private AWSSecurityTokenService mockStsClient;
	
	@Mock
	private TokenRetriever mockTokenRetriever;

	@Mock
	private HttpServletRequest mockHttpRequest;
	
	@Mock
	private HttpGetExecutor mockHttpGetExecutor;
	
	@Mock
	private JWTClaimsExtractor mockJWTClaimsExtractor;
	
	@Mock
	private HttpServletResponse mockHttpResponse;
	
	@Mock
	private ServletOutputStream mockOutputStream;
	
	@Captor
	private ArgumentCaptor<byte[]> byteArrayCaptor;
	
	private static final String SC_CONSOLE_LOGIN_URL = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=token"+
			 "&Issuer=https%3A%2F%2Fwww.foo.com&Destination=https%3A%2F%2Fus-east-1.console.aws.amazon.com%2Fservicecatalog%2Fhome%3Fregion%3Dus-east-1%23%2Fproducts";
	
	private Auth auth = null;
	
	private static final String ID_TOKEN = "id-token";
	private static final String ACCESS_TOKEN = "access-token";
	private static final String USER_INFO_STRING;
	
	static {
		JSONObject claims = new JSONObject();
		JSONArray array = new JSONArray();
		array.put("345678");
		claims.put("team", array);
		USER_INFO_STRING = claims.toString();
	}
	
	private static final String STS_EXPIRES_ON = "2021-10-21T12:59:59Z";
	
	private Claims claims;

	private void mockIncomingUrl(String host, String uri) {
		StringBuffer urlBuffer = new StringBuffer();
		urlBuffer.append(host);
		urlBuffer.append(uri);
		when(mockHttpRequest.getRequestURL()).thenReturn(urlBuffer);
		when(mockHttpRequest.getRequestURI()).thenReturn(uri);
		claims = new DefaultClaims();
		claims.put("team", Collections.singletonList("345678"));
		when(mockJWTClaimsExtractor.extractClaims(ID_TOKEN)).thenReturn(claims);
	}
	
	@Before
	public void before() throws Exception {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
		System.setProperty("AWS_REGION", "us-east-1");
		System.setProperty("SESSION_NAME_CLAIMS", "userid");
		System.setProperty("SESSION_TAG_CLAIMS", "userid,user_name,team");
		System.setProperty(Auth.PROPERTIES_FILENAME_PARAMETER, "test.properties");
		System.setProperty(Auth.SYNAPSE_OAUTH_CLIENT_ID_PARAMETER, "101");
		System.setProperty(Auth.SYNAPSE_OAUTH_CLIENT_SECRET_PARAMETER, "thesecret");
		
		
		mockIncomingUrl("https://www.foo.com", "/bar");

		when(mockHttpResponse.getOutputStream()).thenReturn(mockOutputStream);
		
		AssumeRoleResult assumeRoleResult = new AssumeRoleResult();
		
		Credentials credentials = new Credentials();
		credentials.setAccessKeyId("accessKeyId");
		credentials.setSecretAccessKey("secretAccessKey");
		credentials.setSessionToken("sessionToken");
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		TimeZone tz = TimeZone.getTimeZone("UTC");
		df.setTimeZone(tz);
		credentials.setExpiration(df.parse(STS_EXPIRES_ON));
		assumeRoleResult.setCredentials(credentials);
		when(mockStsClient.assumeRole(any())).thenReturn(assumeRoleResult);
		
		IdAndAccessToken idAndAccessToken = new IdAndAccessToken(new Token(ID_TOKEN, ""), new Token(ACCESS_TOKEN, ""));
		when(mockTokenRetriever.getTokens(anyString(), anyString())).thenReturn(idAndAccessToken);
		
		this.auth = new Auth(mockStsClient, mockHttpGetExecutor, mockTokenRetriever, mockJWTClaimsExtractor);
	}
	
	@After
	public void after() {
		System.clearProperty("TEAM_TO_ROLE_ARN_MAP");
		System.clearProperty("AWS_REGION");
		System.clearProperty("SESSION_TAG_CLAIMS");
		System.clearProperty("SESSION_NAME_CLAIMS");
		System.clearProperty(TEST_PROPERTY_NAME);
		System.clearProperty(Auth.SYNAPSE_OAUTH_CLIENT_ID_PARAMETER);
		System.clearProperty(Auth.SYNAPSE_OAUTH_CLIENT_SECRET_PARAMETER);
	}
	
	@Test
	public void testReadTeamToArnMap() {
		Map<String,String> map = auth.getTeamToRoleMap();
		assertEquals(2, map.size());
		String key = map.keySet().iterator().next();
		assertEquals("123456", key);
		assertEquals("arn:aws:iam::foo", map.get(key));
	}
	
	@Test
	public void testGetAuthUrl() {
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims="
				+ "{\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},"
				+ "\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":"
				+ "{\"essential\":true},\"userid\":{\"essential\":true}}}";
		String actual = auth.getAuthorizeUrl(null);
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetAuthUrlWithState() {
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims="
				+ "{\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},"
				+ "\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":"
				+ "{\"essential\":true},\"userid\":{\"essential\":true}}}&state=some-state";
		String actual = auth.getAuthorizeUrl("some-state");
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetPropertyFromGlobalPropertiesFile() {
		String value = "testPropertyValue";
		
		assertEquals(value, auth.getProperty(TEST_PROPERTY_NAME));
		
	}
	
	@Test
	public void testGetPropertyOverridingFileWithProperty() {
		String value = "someOtherValue";
		System.setProperty(TEST_PROPERTY_NAME, value);
		assertEquals(value, auth.getProperty(TEST_PROPERTY_NAME));
	}

	@Test
	public void testGetMissingOptionalProperty() {
		Assume.assumeTrue(System.getProperty("SKIP_AWS")==null);
		assertNull(auth.getProperty("undefined-property", false));
	}
	
	@Test
	public void testGetSSMParameter() {
		Assume.assumeTrue(System.getProperty("SKIP_AWS")==null);
		// we only want to run this test if we can connect to AWS
		AWSCredentials credentials = null;
		try {
			credentials = DefaultAWSCredentialsProviderChain.getInstance().getCredentials();
		} catch (SdkClientException e) {
			Assume.assumeNoException(e);
		}
		Assume.assumeNotNull(credentials, credentials.getAWSAccessKeyId(), credentials.getAWSSecretKey());
		
		String propertyName = UUID.randomUUID().toString();
		String ssmKey = UUID.randomUUID().toString();
		String propertyValue = UUID.randomUUID().toString();
		
		// the property has NOT been stored yet
		assertNull(auth.getProperty(propertyName, false));
		
		System.setProperty(propertyName, "ssm::"+ssmKey);
		
		// now let's store the property in SSM
		try {
			AWSSimpleSystemsManagement ssmClient = AWSSimpleSystemsManagementClientBuilder.defaultClient();
			
			PutParameterRequest putParameterRequest = new PutParameterRequest();
			putParameterRequest.setName(ssmKey);
			putParameterRequest.setValue(propertyValue);
			putParameterRequest.setType(ParameterType.SecureString);
			ssmClient.putParameter(putParameterRequest);
		} catch (AmazonClientException e) {
			// cannot continue with this integration test
			return;
		}
		
		// verify that the property is now available
		assertEquals(propertyValue, auth.getProperty(propertyName, false));
	}
		
	@Test
	public void testGetSSMParameterMissingValue() {
		Assume.assumeTrue(System.getProperty("SKIP_AWS")==null);

		// we only want to run this test if we can connect to AWS
		AWSCredentials credentials = null;
		try {
			credentials = DefaultAWSCredentialsProviderChain.getInstance().getCredentials();
		} catch (SdkClientException e) {
			Assume.assumeNoException(e);
		}
		Assume.assumeNotNull(credentials, credentials.getAWSAccessKeyId(), credentials.getAWSSecretKey());

		String propertyName = UUID.randomUUID().toString();
		String ssmKey = UUID.randomUUID().toString();

		// the property name hasn't been stored at all
		assertNull(auth.getProperty(propertyName, false));

		// now the property name, and pointer to ssm, are stored, but ssm has no value
		System.setProperty(propertyName, "ssm::"+ssmKey);

		assertNull(auth.getProperty(propertyName, false));
	}

	@Test
	public void testGetConsoleLoginURL() throws Exception {
		when(mockHttpGetExecutor.executeHttpGet(anyString(), eq((String)null))).thenReturn("{\"SigninToken\":\"token\"}");
		
		Credentials credentials = new Credentials();
		credentials.setAccessKeyId("keyId");
		credentials.setSecretAccessKey("keySecret");
		credentials.setSessionToken("token");
		
		// method under test
		String actual = auth.getConsoleLoginURL(mockHttpRequest, credentials);
		
		assertEquals(SC_CONSOLE_LOGIN_URL, actual);
	}
	
	@Test
	public void testIsEntrypointUri() {
		assertTrue(Auth.isOAuthEntrypointUri(null));
		assertTrue(Auth.isOAuthEntrypointUri(""));
		assertTrue(Auth.isOAuthEntrypointUri("/"));
		assertTrue(Auth.isOAuthEntrypointUri("/ststoken"));
		assertTrue(Auth.isOAuthEntrypointUri("/accesstoken"));
		assertTrue(Auth.isOAuthEntrypointUri("/idtoken"));
		
		assertFalse(Auth.isOAuthEntrypointUri("/synapse"));
		assertFalse(Auth.isOAuthEntrypointUri("/about"));
		assertFalse(Auth.isOAuthEntrypointUri("/random"));
	}
	
	@Test
	public void tesGgetRequestTypeFromUri() {
		assertEquals(RequestType.SC_CONSOLE, Auth.getRequestTypeFromUri("/"));
		assertEquals(RequestType.SC_CONSOLE, Auth.getRequestTypeFromUri(""));
		assertEquals(RequestType.SC_CONSOLE, Auth.getRequestTypeFromUri(null));
		assertEquals(RequestType.STS_TOKEN, Auth.getRequestTypeFromUri("/ststoken"));
		assertEquals(RequestType.ACCESS_TOKEN, Auth.getRequestTypeFromUri("/accesstoken"));
		assertEquals(RequestType.ID_TOKEN, Auth.getRequestTypeFromUri("/idtoken"));
		assertThrows(IllegalArgumentException.class, ()->{Auth.getRequestTypeFromUri("/about");});
	}
	
	@Test 
	public void testCreateAssumeRoleRequest() throws Exception {
		String selectedTeam = "10101";
		String roleArn = "arn:aws:iam::foo";
		String userid = "1";

		System.setProperty("SESSION_NAME_CLAIMS", "userid,user_name");
		
		Claims claims = new DefaultClaims();
		List<String> teams = new ArrayList<String>();
		teams.add("888");
		teams.add("999");
		claims.put("team", teams);
		claims.put("userid", userid);
		claims.put("user_name", "aname");

		// method under test
		AssumeRoleRequest request = auth.createAssumeRoleRequest(claims, roleArn, selectedTeam);
		
		assertEquals(roleArn, request.getRoleArn());
		assertEquals("1:aname", request.getRoleSessionName());
		
		assertEquals(4, request.getTags().size());

		assertTrue(request.getTags().contains((new Tag()).withKey("synapse-user_name").withValue("aname")));
		assertTrue(request.getTags().contains((new Tag()).withKey("synapse-userid").withValue("1")));
		assertTrue(request.getTags().contains((new Tag()).withKey("synapse-team").withValue("10101")));
		
		boolean containsNonceTag = false;
		for (Tag tag : request.getTags()) {
			if (tag.getKey().equals("synapse-nonce") && StringUtils.isNotEmpty(tag.getValue())) {
				containsNonceTag = true;
			}
		}
		assertTrue(containsNonceTag);
		
	}

	@Test
	public void testInitApp() {
		String version = auth.getAppVersion();
		assertEquals(String.format("%1$s-%2$s", "20200201-11:55", "0.1-3-g8eda288"), version);
	}
	
	@Test
	public void testRedirectURIs() {
		System.setProperty("REDIRECT_URIS", "foo,bar");
		
		List<String> expected = new ArrayList<String>();
		expected.add("foo");
		expected.add("bar");
		
		assertEquals(expected, auth.getRedirectURIs("baz"));
	}

	@Test
	public void testRedirectURIsDefault() {
		System.clearProperty("REDIRECT_URIS");
		
		assertEquals(Collections.singletonList("baz"), auth.getRedirectURIs("baz"));
	}

	@Test
	public void testSanitizeValues() {
		assertEquals("Sage-Bionetworks  A Better Science Company ", Auth.sanitizeTagValue("Sage-Bionetworks (A Better Science Company)"));
		assertEquals("abc XYZ 123  _.:/=+ -@", Auth.sanitizeTagValue("abc XYZ 123 \t_.:/=+\\-@"));
		assertEquals("                  ", Auth.sanitizeTagValue("!#$%^&*(){}|\"';<>,"));
	}

	@Test
	public void testRedirectToSCConsole() throws Exception {
		String selectedTeam = "10101";
		String roleArn = "arn:aws:iam::foo";

		System.setProperty("SESSION_NAME_CLAIMS", "userid,user_name");
		
		Claims claims = new DefaultClaims();

		when(mockHttpGetExecutor.executeHttpGet(anyString(), eq((String)null))).thenReturn("{\"SigninToken\":\"token\"}");
		
		// method under test
		auth.redirectToSCConsole(claims, roleArn, selectedTeam, mockHttpRequest, mockHttpResponse);
		
		verify(mockHttpResponse).setStatus(303);
		verify(mockHttpResponse).setHeader("Location", SC_CONSOLE_LOGIN_URL);
	}
	

	@Test
	public void testWriteFileToResponse() throws Exception {
		String expectedContent = "file-content";
		byte[] expectedBytes = expectedContent.getBytes(Charset.forName("UTF8"));
		
		// method under test
		Auth.displayResponse(expectedContent, "text/plain", mockHttpResponse);
		
		verify(mockHttpResponse).setStatus(200);
		verify(mockHttpResponse).setContentType("text/plain");
		verify(mockHttpResponse).setCharacterEncoding("utf-8");
		verify(mockHttpResponse).setHeader("Content-Transfer-Encoding", "binary");
		verify(mockHttpResponse).setHeader("Cache-Control", "no-store, no-cache");
		verify(mockOutputStream).write(expectedBytes);
		verify(mockHttpResponse).setContentLength(expectedBytes.length);		
		verify(mockOutputStream).flush();
	}
	
	@Test
	public void testReturnStsToken() throws Exception {
		String selectedTeam = "10101";
		String roleArn = "arn:aws:iam::foo";

		System.setProperty("SESSION_NAME_CLAIMS", "userid,user_name");
		
		Claims claims = new DefaultClaims();
		
		// method under test
		auth.returnStsToken(claims, roleArn, selectedTeam, mockHttpResponse);
		
		verify(mockOutputStream).write(byteArrayCaptor.capture());
		JSONObject actual = new JSONObject(new String(byteArrayCaptor.getValue(),Charset.forName("UTF8")));
		assertEquals("accessKeyId", actual.getString("AccessKeyId"));
		assertEquals("secretAccessKey", actual.getString("SecretAccessKey"));
		assertEquals("sessionToken", actual.getString("SessionToken"));
		assertEquals(1, actual.getInt("Version"));
		assertEquals(STS_EXPIRES_ON, actual.getString("Expiration"));
		
		verify(mockHttpResponse).setContentType("application/json");
		verify(mockHttpResponse).setContentLength(byteArrayCaptor.getValue().length);		
	}
	
	@Test
	public void testCreateJSONfile() throws Exception {
		Map<String,Object> content = new LinkedHashMap<String,Object>();
		content.put("key1", "foo");
		content.put("key2", 99);
		String expectedJson = "{\"key1\":\"foo\",\"key2\":99}";
		
		// method under test
		assertEquals(expectedJson, Auth.createSerializedJSON(content));
	}
	
	@Test
	public void testReturnToken() throws Exception {
		String expectedContent = "token";
		byte[] expectedBytes = expectedContent.getBytes(Charset.forName("UTF8"));
		
		// method under test
		auth.returnOidcToken(expectedContent, mockHttpResponse);
		
		verify(mockHttpResponse).setContentType("text/plain");
		verify(mockOutputStream).write(expectedBytes);
		verify(mockHttpResponse).setContentLength(expectedBytes.length);		
	}
	
	@Test
	public void testDoPost() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/");

		// method under test
		auth.doPost(mockHttpRequest, mockHttpResponse);
		verify(mockHttpResponse).setStatus(404);
	}
	
	@Test
	public void testDoGet_RedirectUrl() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/");

		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		verify(mockHttpResponse).setStatus(303);
		String expectedRedirURL = "https://signin.synapse.org?response_type=code&client_id=101&"
				+ "redirect_uri=https%3A%2F%2Fwww.foo.com%2Fsynapse&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},"
				+ "\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}},\"userinfo\":"
				+ "{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},"
				+ "\"userid\":{\"essential\":true}}}&state=SC_CONSOLE&scope=openid";
		verify(mockHttpResponse).setHeader("Location", expectedRedirURL);
	}
	
	
	@Test
	public void testDoGet_redirectToSCconsole() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/synapse");
		when(mockHttpRequest.getParameter("code")).thenReturn("some-code");
		when(mockHttpRequest.getParameter("state")).thenReturn(RequestType.SC_CONSOLE.name());

		when(mockHttpGetExecutor.executeHttpGet(anyString(), eq((String)null))).thenReturn("{\"SigninToken\":\"token\"}");

		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		verify(mockHttpResponse).setStatus(303);
		verify(mockHttpResponse).setHeader("Location", SC_CONSOLE_LOGIN_URL);
	}
	
	@Test
	public void testDoGet_DownloadSTSToken() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/synapse");
		when(mockHttpRequest.getParameter("code")).thenReturn("some-code");
		when(mockHttpRequest.getParameter("state")).thenReturn(RequestType.STS_TOKEN.name());

		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		verify(mockOutputStream).write(byteArrayCaptor.capture());
		JSONObject actual = new JSONObject(new String(byteArrayCaptor.getValue(),Charset.forName("UTF8")));
		assertEquals("accessKeyId", actual.getString("AccessKeyId"));
		assertEquals("secretAccessKey", actual.getString("SecretAccessKey"));
		assertEquals("sessionToken", actual.getString("SessionToken"));
		verify(mockHttpResponse).setContentLength(byteArrayCaptor.getValue().length);
		verify(mockHttpResponse).setContentType("application/json");
	}
	
	@Test
	public void testDoGet_DownloadAccessToken() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/synapse");
		when(mockHttpRequest.getParameter("code")).thenReturn("some-code");
		when(mockHttpRequest.getParameter("state")).thenReturn(RequestType.ACCESS_TOKEN.name());

		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		byte[] expectedBytes = ACCESS_TOKEN.getBytes(Charset.forName("UTF8"));
		verify(mockOutputStream).write(expectedBytes);
		verify(mockHttpResponse).setContentLength(expectedBytes.length);		
		verify(mockHttpResponse).setContentType("text/plain");
	}
	
	@Test
	public void testDoGet_DownloadIdToken() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/synapse");
		when(mockHttpRequest.getParameter("code")).thenReturn("some-code");
		when(mockHttpRequest.getParameter("state")).thenReturn(RequestType.ACCESS_TOKEN.name());

		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		byte[] expectedBytes = ACCESS_TOKEN.getBytes(Charset.forName("UTF8"));
		verify(mockOutputStream).write(expectedBytes);
		verify(mockHttpResponse).setContentLength(expectedBytes.length);		
		verify(mockHttpResponse).setContentType("text/plain");
	}
	
	@Test
	public void testDoGet_DownloadSTSTokenViaWebServiceRequest() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/ststoken");
		when(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer access-token");
		when(mockHttpGetExecutor.executeHttpGet("https://repo-prod.prod.sagebase.org/auth/v1/oauth2/userinfo",
				"access-token")).thenReturn(USER_INFO_STRING);
		
		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		verify(mockOutputStream).write(byteArrayCaptor.capture());
		JSONObject actual = new JSONObject(new String(byteArrayCaptor.getValue(),Charset.forName("UTF8")));
		assertEquals("accessKeyId", actual.getString("AccessKeyId"));
		assertEquals("secretAccessKey", actual.getString("SecretAccessKey"));
		assertEquals("sessionToken", actual.getString("SessionToken"));
		verify(mockHttpResponse).setContentLength(byteArrayCaptor.getValue().length);		
		verify(mockHttpResponse).setContentType("application/json");
	}
	
	@Test
	public void testDoGet_DownloadSTSTokenViaWebServiceRequest_Unauthorized() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/ststoken");
		when(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer access-token");
		when(mockHttpGetExecutor.executeHttpGet("https://repo-prod.prod.sagebase.org/auth/v1/oauth2/userinfo",
				"access-token")).thenThrow(new HttpException(403, "Forbidden", null));
		
		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		verify(mockOutputStream).println("Error: Forbidden");
		verify(mockHttpResponse).setContentType("text/plain");
		verify(mockHttpResponse).setStatus(403);
	}
	
	@Test
	public void testDoGet_unknown() throws Exception {
		mockIncomingUrl("https://www.foo.com", "/unknown");

		// method under test
		auth.doGet(mockHttpRequest, mockHttpResponse);
		
		verify(mockHttpResponse).setStatus(303);
		verify(mockHttpResponse).setHeader("Location", "https://www.foo.com");
	}
	
}
