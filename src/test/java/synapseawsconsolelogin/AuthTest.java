package synapseawsconsolelogin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

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
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClientBuilder;
import com.amazonaws.services.simplesystemsmanagement.model.ParameterType;
import com.amazonaws.services.simplesystemsmanagement.model.PutParameterRequest;

@RunWith(MockitoJUnitRunner.class)
public class AuthTest {
	
	private static final String TEST_PROPERTY_NAME = "testPropertyName";

	@Mock
	private HttpServletRequest req;
	
	@Mock
	private HttpGetExecutor mockHttpGetExecutor;
	
	@Before
	public void before() {
		System.setProperty("TEAM_TO_ROLE_ARN_MAP","[{\"teamId\":\"123456\",\"roleArn\":\"arn:aws:iam::foo\"},{\"teamId\":\"345678\",\"roleArn\":\"arn:aws:iam::bar\"}]");
		System.setProperty("AWS_REGION", "us-east-1");
		System.setProperty("USER_CLAIMS", "userid,user_name");
		System.setProperty(Auth.PROPERTIES_FILENAME_PARAMETER, "test.properties");
	}
	
	@After
	public void after() {
		System.clearProperty("TEAM_TO_ROLE_ARN_MAP");
		System.clearProperty("AWS_REGION");
		System.clearProperty("USER_CLAIMS");
		System.clearProperty(TEST_PROPERTY_NAME);
	}
	
	@Test
	public void testReadTeamToArnMap() {
		Auth auth = new Auth();
		
		Map<String,String> map = auth.getTeamToRoleMap();
		assertEquals(2, map.size());
		String key = map.keySet().iterator().next();
		assertEquals("123456", key);
		assertEquals("arn:aws:iam::foo", map.get(key));
	}
	
	@Test
	public void testGetAuthUrl() {
		Auth auth = new Auth();
		
		String expected = "https://signin.synapse.org?response_type=code&client_id=%s&redirect_uri=%s&claims={\"id_token\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"userid\":{\"essential\":true},\"user_name\":{\"essential\":true}},\"userinfo\":{\"team\":{\"values\":[\"123456\",\"345678\"]},\"userid\":{\"essential\":true},\"user_name\":{\"essential\":true}}}";
		String actual = auth.getAuthorizeUrl();
		assertEquals(expected, actual);
	}
	
	@Test
	public void testGetPropertyFromGlobalPropertiesFile() {
		String value = "testPropertyValue";
		Auth auth = new Auth();
		
		assertEquals(value, auth.getProperty(TEST_PROPERTY_NAME));
		
	}
	
	@Test
	public void testGetPropertyOverridingFileWithProperty() {
		String value = "someOtherValue";
		System.setProperty(TEST_PROPERTY_NAME, value);
		Auth auth = new Auth();
		assertEquals(value, auth.getProperty(TEST_PROPERTY_NAME));
	}

	@Test
	public void testGetMissingOptionalProperty() {
		Assume.assumeTrue(System.getProperty("SKIP_AWS")==null);
		Auth auth = new Auth();
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
		
		Auth auth = new Auth();
		
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

		Auth auth = new Auth();

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
		when(req.getRequestURL()).thenReturn(urlBuffer);
		when(req.getRequestURI()).thenReturn("/bar");
		when(mockHttpGetExecutor.executeHttpGet(anyString())).thenReturn("{\"SigninToken\":\"token\"}");
		
		Credentials credentials = new Credentials();
		credentials.setAccessKeyId("keyId");
		credentials.setSecretAccessKey("keySecret");
		credentials.setSessionToken("token");
		
		Auth auth = new Auth();
		
		// method under test
		String actual = auth.getConsoleLoginURL(req, credentials, mockHttpGetExecutor);
		
		String expected = "https://signin.aws.amazon.com/federation?Action=login&SigninToken=token"+
				 "&Issuer=https%3Awww.foo.com&Destination=https%3A%2F%2Fus-east-1.console.aws.amazon.com%2Fservicecatalog%2Fhome%3Fregion%3Dus-east-1%23%2Fproducts";
		
		assertEquals(expected, actual);
	}

	@Test
	public void testInitApp() {
		Auth auth = new Auth();
		String version = auth.getAppVersion();
		assertEquals(String.format("%1$s-%2$s", "20200201-11:55", "6dc2fec"), version);
	}

}
