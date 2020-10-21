package synapseawsconsolelogin;

import static org.junit.Assert.*;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.*;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.amazonaws.AmazonClientException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.marketplacemetering.model.ResolveCustomerResult;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
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
	private static final String USER_ID = "101";

	@Mock
	private HttpServletRequest mockServletRequest;
	
	@Mock
	private HttpServletResponse mockServletResponse;
	
	@Mock
	private ServletOutputStream mockServletOutputStream;
	
	@Mock
	private HttpGetExecutor mockHttpGetExecutor;
	
	@Mock
	private DynamoDbHelper dynamoDbHelper;
	
	@Mock
	private MarketplaceMeteringHelper marketplaceMeteringHelper;
	
	@Before
	public void before() {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
		System.setProperty("AWS_REGION", "us-east-1");
		System.setProperty("SESSION_NAME_CLAIMS", "userid");
		System.setProperty("SESSION_TAG_CLAIMS", "userid,user_name,team");
		System.setProperty(Auth.PROPERTIES_FILENAME_PARAMETER, "test.properties");
	}
	
	@After
	public void after() {
		System.clearProperty("TEAM_TO_ROLE_ARN_MAP");
		System.clearProperty("AWS_REGION");
		System.clearProperty("SESSION_TAG_CLAIMS");
		System.clearProperty("SESSION_NAME_CLAIMS");
		System.clearProperty("SYNAPSE_OAUTH_CLIENT_ID");
		System.clearProperty(TEST_PROPERTY_NAME);
		System.clearProperty("MARKETPLACE_PRODUCT_CODE");
	}
	
	@Test
	public void testReadTeamToArnMap() {
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		Map<String,String> map = auth.getTeamToRoleMap();
		assertEquals(2, map.size());
		String key = map.keySet().iterator().next();
		assertEquals("123456", key);
		assertEquals("arn:aws:iam::foo", map.get(key));
	}
	
	@Test
	public void testGetAuthUrl() throws UnsupportedEncodingException {
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}}}";
		String actual = auth.getAuthorizeUrl(null);
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetAuthUrlUserIDAlwaysIncluded() throws UnsupportedEncodingException {
		// removing 'userId' from SESSION_NAME_CLAIMS and SESSION_TAG_CLAIMS doesn't change anything userId is always requested
		System.setProperty("SESSION_NAME_CLAIMS", "");
		System.setProperty("SESSION_TAG_CLAIMS", "user_name,team");
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}}}";
		String actual = auth.getAuthorizeUrl(null);
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetAuthUrlWithState() throws UnsupportedEncodingException {
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}}}&state=state";
		String actual = auth.getAuthorizeUrl("state");
		assertEquals(expected, actual);
	}
	
	@Test
	public void handleSubscribe() throws Exception {
		System.setProperty("SYNAPSE_OAUTH_CLIENT_ID", "101");		
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String marketplaceToken = "marketplace-token";
		String baseUrl = "https://baseurl";
		
		StringBuffer sb = new StringBuffer();
		sb.append(baseUrl);
		when(mockServletRequest.getRequestURL()).thenReturn(sb);
		when(mockServletRequest.getRequestURI()).thenReturn(baseUrl);
		when(mockServletRequest.getHeader("x-amzn-marketplace-token")).thenReturn(marketplaceToken);
		
		// method under test
		auth.handleSubscribe(mockServletRequest, mockServletResponse);
		
		String expectedRedirUrl = "https://signin.synapse.org?response_type=code&client_id=101&redirect_uri=%2Fsynapse&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"user_name\":{\"essential\":true},\"userid\":{\"essential\":true}}}&state=marketplace-token&scope=openid";
		verify(mockServletResponse).setHeader("Location", expectedRedirUrl);
		verify(mockServletResponse).setStatus(303);
	}
	
	@Test
	public void handleSubscribeNoMarketplaceToken() throws Exception {	
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		when(mockServletResponse.getOutputStream()).thenReturn(mockServletOutputStream);
		
		// method under test
		auth.handleSubscribe(mockServletRequest, mockServletResponse);
		
		verify(mockServletResponse).setStatus(400);
		verify(mockServletOutputStream).println("Missing x-amzn-marketplace-token header");
	}
	
	@Test
	public void testRegisterCustomer() throws Exception {
		String marketplaceProductCode = "product-code";
		System.setProperty("MARKETPLACE_PRODUCT_CODE", marketplaceProductCode);
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String marketplaceToken = "marketplace/token";
		String urlEncodedMarketplaceToken = URLEncoder.encode(marketplaceToken, "UTF-8");
		
		when(mockServletRequest.getParameter("state")).thenReturn(urlEncodedMarketplaceToken);
		ResolveCustomerResult resolveCustomerResult = new ResolveCustomerResult();
		String customerIdentifier = "customer-id";
		resolveCustomerResult.setCustomerIdentifier(customerIdentifier);
		resolveCustomerResult.setProductCode(marketplaceProductCode);
		when(marketplaceMeteringHelper.resolveCustomer(marketplaceToken)).thenReturn(resolveCustomerResult);
		
		when(dynamoDbHelper.getMarketplaceCustomerIdForUser(USER_ID)).thenReturn(null);
		
		// method under test
		boolean b = auth.registerCustomer(mockServletRequest, mockServletResponse, USER_ID);
		
		assertTrue(b);
		verify(marketplaceMeteringHelper).resolveCustomer(marketplaceToken);
		verify(dynamoDbHelper).getMarketplaceCustomerIdForUser(USER_ID);
		verify(dynamoDbHelper).addMarketplaceId(USER_ID, marketplaceProductCode, customerIdentifier);
	}
	
	@Test
	public void testRegisterCustomerNoToken() throws Exception {
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		when(mockServletRequest.getParameter("state")).thenReturn(null);
		
		// method under test
		boolean b = auth.registerCustomer(mockServletRequest, mockServletResponse, USER_ID);
		
		assertTrue(b);
		verify(marketplaceMeteringHelper, never()).resolveCustomer(anyString());
		verify(dynamoDbHelper, never()).getMarketplaceCustomerIdForUser(anyString());
		verify(dynamoDbHelper, never()).addMarketplaceId(anyString(), anyString(), anyString());
	}
	
	@Test
	public void testRegisterCustomerWrongProductCode() throws Exception {
		String marketplaceProductCode = "product-code";
		System.setProperty("MARKETPLACE_PRODUCT_CODE", marketplaceProductCode);
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String marketplaceToken = "marketplace/token";
		String urlEncodedMarketplaceToken = URLEncoder.encode(marketplaceToken, "UTF-8");
		
		when(mockServletRequest.getParameter("state")).thenReturn(urlEncodedMarketplaceToken);
		ResolveCustomerResult resolveCustomerResult = new ResolveCustomerResult();
		String customerIdentifier = "customer-id";
		resolveCustomerResult.setCustomerIdentifier(customerIdentifier);
		resolveCustomerResult.setProductCode("some other product code");
		when(marketplaceMeteringHelper.resolveCustomer(marketplaceToken)).thenReturn(resolveCustomerResult);
		
		
		// method under test
		try {
			auth.registerCustomer(mockServletRequest, mockServletResponse, USER_ID);
			fail("Expected RuntimeException");
		} catch (RuntimeException e) {
			// as expected
		}
		
		verify(marketplaceMeteringHelper).resolveCustomer(marketplaceToken);
		verify(dynamoDbHelper, never()).getMarketplaceCustomerIdForUser(anyString());
		verify(dynamoDbHelper, never()).addMarketplaceId(anyString(), anyString(), anyString());
	}
	
	@Test
	public void testRegisterCustomerAlreadyRegistered() throws Exception {
		String marketplaceProductCode = "product-code";
		System.setProperty("MARKETPLACE_PRODUCT_CODE", marketplaceProductCode);
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String marketplaceToken = "marketplace/token";
		String urlEncodedMarketplaceToken = URLEncoder.encode(marketplaceToken, "UTF-8");
		
		when(mockServletRequest.getParameter("state")).thenReturn(urlEncodedMarketplaceToken);
		ResolveCustomerResult resolveCustomerResult = new ResolveCustomerResult();
		String customerIdentifier = "customer-id";
		resolveCustomerResult.setCustomerIdentifier(customerIdentifier);
		resolveCustomerResult.setProductCode(marketplaceProductCode);
		when(marketplaceMeteringHelper.resolveCustomer(marketplaceToken)).thenReturn(resolveCustomerResult);
		
		when(dynamoDbHelper.getMarketplaceCustomerIdForUser(USER_ID)).thenReturn(customerIdentifier);
		
		// method under test
		boolean b = auth.registerCustomer(mockServletRequest, mockServletResponse, USER_ID);
		
		assertTrue(b);
		verify(marketplaceMeteringHelper).resolveCustomer(marketplaceToken);
		verify(dynamoDbHelper).getMarketplaceCustomerIdForUser(USER_ID);
		verify(dynamoDbHelper, never()).addMarketplaceId(anyString(), anyString(), anyString());
	}
	
	@Test
	public void testRegisterCustomerAlreadyRegisteredDifferentCustomer() throws Exception {
		String marketplaceProductCode = "product-code";
		System.setProperty("MARKETPLACE_PRODUCT_CODE", marketplaceProductCode);
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		String marketplaceToken = "marketplace/token";
		String urlEncodedMarketplaceToken = URLEncoder.encode(marketplaceToken, "UTF-8");
		
		when(mockServletRequest.getParameter("state")).thenReturn(urlEncodedMarketplaceToken);
		ResolveCustomerResult resolveCustomerResult = new ResolveCustomerResult();
		String customerIdentifier = "customer-id";
		resolveCustomerResult.setCustomerIdentifier(customerIdentifier);
		resolveCustomerResult.setProductCode(marketplaceProductCode);
		when(marketplaceMeteringHelper.resolveCustomer(marketplaceToken)).thenReturn(resolveCustomerResult);
		
		when(dynamoDbHelper.getMarketplaceCustomerIdForUser(USER_ID)).thenReturn("some other customer id");
		
		// method under test
		boolean b = auth.registerCustomer(mockServletRequest, mockServletResponse, USER_ID);
		
		assertFalse(b);
		verify(marketplaceMeteringHelper).resolveCustomer(marketplaceToken);
		verify(dynamoDbHelper).getMarketplaceCustomerIdForUser(USER_ID);
		verify(dynamoDbHelper, never()).addMarketplaceId(anyString(), anyString(), anyString());
	}
	
	@Test
	public void testGetPropertyFromGlobalPropertiesFile() {
		String value = "testPropertyValue";
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		assertEquals(value, auth.getProperty(TEST_PROPERTY_NAME));
		
	}
	
	@Test
	public void testGetPropertyOverridingFileWithProperty() {
		String value = "someOtherValue";
		System.setProperty(TEST_PROPERTY_NAME, value);
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		assertEquals(value, auth.getProperty(TEST_PROPERTY_NAME));
	}

	@Test
	public void testGetMissingOptionalProperty() {
		Assume.assumeTrue(System.getProperty("SKIP_AWS")==null);
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
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
		
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
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

		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);

		// the property name hasn't been stored at all
		assertNull(auth.getProperty(propertyName, false));

		// now the property name, and pointer to ssm, are stored, but ssm has no value
		System.setProperty(propertyName, "ssm::"+ssmKey);

		assertNull(auth.getProperty(propertyName, false));
	}

	@Test
	public void testGetConsoleLoginURL() throws Exception {
		StringBuffer urlBuffer = new StringBuffer();
		urlBuffer.append("https:www.foo.com/bar");
		when(mockServletRequest.getRequestURL()).thenReturn(urlBuffer);
		when(mockServletRequest.getRequestURI()).thenReturn("/bar");
		when(mockHttpGetExecutor.executeHttpGet(anyString())).thenReturn("{\"SigninToken\":\"token\"}");
		
		Credentials credentials = new Credentials();
		credentials.setAccessKeyId("keyId");
		credentials.setSecretAccessKey("keySecret");
		credentials.setSessionToken("token");
		
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		// method under test
		String actual = auth.getConsoleLoginURL(mockServletRequest, credentials, mockHttpGetExecutor);
		
		String expected = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=token"+
				 "&Issuer=https%3Awww.foo.com&Destination=https%3A%2F%2Fus-east-1.console.aws.amazon.com%2Fservicecatalog%2Fhome%3Fregion%3Dus-east-1%23%2Fproducts";
		
		assertEquals(expected, actual);
	}
	
	@Test 
	public void testCreateAssumeRoleRequest() throws Exception {
		String selectedTeam = "10101";
		String roleArn = "arn:aws:iam::foo";
		String userid = "1";

		System.setProperty("SESSION_NAME_CLAIMS", "userid,user_name");
		
		Claims claims = new DefaultClaims();
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
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
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		String version = auth.getAppVersion();
		assertEquals(String.format("%1$s-%2$s", "20200201-11:55", "0.1-3-g8eda288"), version);
	}
	
	@Test
	public void testRedirectURIs() {
		System.setProperty("REDIRECT_URIS", "foo,bar");
		
		List<String> expected = new ArrayList<String>();
		expected.add("foo");
		expected.add("bar");
		
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		assertEquals(expected, auth.getRedirectURIs("baz"));
	}

	@Test
	public void testRedirectURIsDefault() {
		System.clearProperty("REDIRECT_URIS");
		
		Auth auth = new Auth(dynamoDbHelper, marketplaceMeteringHelper);
		
		assertEquals(Collections.singletonList("baz"), auth.getRedirectURIs("baz"));
	}

	@Test
	public void testSanitizeValues() {
		assertEquals("Sage-Bionetworks  A Better Science Company ", Auth.sanitizeTagValue("Sage-Bionetworks (A Better Science Company)"));
		assertEquals("abc XYZ 123  _.:/=+ -@", Auth.sanitizeTagValue("abc XYZ 123 \t_.:/=+\\-@"));
		assertEquals("                  ", Auth.sanitizeTagValue("!#$%^&*(){}|\"';<>,"));
	}

}
