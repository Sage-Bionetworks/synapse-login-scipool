package synapseawsconsolelogin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;

@RunWith(MockitoJUnitRunner.class)
public class DynamoDbHelperTest {
	@Mock
	private AmazonDynamoDB mockAmazonDynamoDB;
	
	private DynamoDbHelper dynamoDbHelper;
	
	@Captor
	ArgumentCaptor<PutItemRequest> putItemRequestCaptor;
	
	@Captor
	ArgumentCaptor<GetItemRequest> getItemRequestCaptor;
	
	private static final String TABLE_NAME = "table-name";
	
	@Before
	public void setUp() throws Exception {
		dynamoDbHelper = new DynamoDbHelper(TABLE_NAME, mockAmazonDynamoDB);
	}
	
	
	@Test
	public void testAddMarketplaceId() {
		// create a record
		String userId = "some-user-id";
		String productCode = "some-product-code";
		String customerIdentifier = "some-customer-id";
		
		// method under test
		dynamoDbHelper.addMarketplaceId(userId, productCode, customerIdentifier);
		
		verify(mockAmazonDynamoDB).putItem(putItemRequestCaptor.capture());
		
		assertEquals(TABLE_NAME, putItemRequestCaptor.getValue().getTableName());
		
		Map<String, AttributeValue> itemToAdd = putItemRequestCaptor.getValue().getItem();
		
		assertEquals(userId, itemToAdd.get("userId").getS());
		assertEquals(productCode, itemToAdd.get("productCode").getS());
		assertEquals(customerIdentifier, itemToAdd.get("marketplaceCustomerId").getS());
	}

	@Test
	public void testGetMarketplaceCustomerIdForUser() {
		// create a record
		String userId = "some-user-id";
		String customerId = "some-customer-id";
		
		GetItemResult getItemResult = new GetItemResult();
		AttributeValue attributeValue = new AttributeValue().withS(customerId);
		getItemResult.addItemEntry("marketplaceCustomerId", attributeValue);
		when(mockAmazonDynamoDB.getItem((GetItemRequest)any())).thenReturn(getItemResult);

		// method under test
		String actualCustomerId = dynamoDbHelper.getMarketplaceCustomerIdForUser(userId);
		
		verify(mockAmazonDynamoDB).getItem(getItemRequestCaptor.capture());
		
		GetItemRequest getItemRequest = getItemRequestCaptor.getValue();
		
		assertEquals(TABLE_NAME, getItemRequest.getTableName());
		assertEquals(userId, getItemRequest.getKey().get("userId").getS());
		
		List<String> expectedAttributes = Arrays.asList(new String[] {"productCode", "marketplaceCustomerId"});
		assertEquals(expectedAttributes, getItemRequest.getAttributesToGet());
		assertTrue(getItemRequest.getConsistentRead());
		
		assertEquals(customerId, actualCustomerId);
		
	}

	@Test
	public void testGetMarketplaceCustomerIdForUserMissingEntry() {
		// create a record
		String userId = "some-user-id";

		GetItemResult getItemResult = new GetItemResult();
		when(mockAmazonDynamoDB.getItem((GetItemRequest)any())).thenReturn(getItemResult);
		
		// method under test
		String actualCustomerId = dynamoDbHelper.getMarketplaceCustomerIdForUser(userId);
		
		verify(mockAmazonDynamoDB).getItem(getItemRequestCaptor.capture());
		
		GetItemRequest getItemRequest = getItemRequestCaptor.getValue();
		
		assertEquals(TABLE_NAME, getItemRequest.getTableName());
		assertEquals(userId, getItemRequest.getKey().get("userId").getS());
		
		List<String> expectedAttributes = Arrays.asList(new String[] {"productCode", "marketplaceCustomerId"});
		assertEquals(expectedAttributes, getItemRequest.getAttributesToGet());
		assertTrue(getItemRequest.getConsistentRead());
		
		assertNull(actualCustomerId);
		
	}

}
