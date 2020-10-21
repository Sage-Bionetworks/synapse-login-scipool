package synapseawsconsolelogin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.DeleteTableRequest;
import com.amazonaws.services.dynamodbv2.model.DescribeTableResult;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.KeyType;
import com.amazonaws.services.dynamodbv2.model.ResourceNotFoundException;
import com.amazonaws.services.dynamodbv2.model.ScalarAttributeType;

/*
 * Note: We run this test once, in a local build, to verify that the access to the DynamoDB table is correct.
 * The test is 'ignored' when checked in so that the CI/CD system does not have to create or delete an actual
 * table in AWS.
 */
public class DynamoDbHelperTest {
	private static final String TABLE_NAME = "TEST_TABLE";
	private static final long TIME_TO_WAIT_FOR_TABLE_OPERATION_MILLISEC = 1000*60; // creation or deletion, one minute
	private AmazonDynamoDB amazonDynamoDB;
	private DynamoDbHelper dynamoDbHelper;
	
	private static Logger logger = Logger.getLogger("DynamoDbHelperTest");

	
	@Before
	public void setUp() throws Exception {
		amazonDynamoDB = AmazonDynamoDBClientBuilder.defaultClient();
		
		// if already created, delete it
		try {
			deleteTable();
		} catch (ResourceNotFoundException e) {
			// OK, continue
		}
		
		
		// create table
		CreateTableRequest createTableRequest = new CreateTableRequest();
		AttributeDefinition attributeDefinition = new AttributeDefinition();
		attributeDefinition.setAttributeName("userId");
		attributeDefinition.setAttributeType(ScalarAttributeType.S);
		createTableRequest.setAttributeDefinitions(Collections.singletonList(attributeDefinition));
		createTableRequest.setBillingMode("PAY_PER_REQUEST");
		KeySchemaElement keySchemaElement = new KeySchemaElement();
		keySchemaElement.setAttributeName("userId");
		keySchemaElement.setKeyType(KeyType.HASH);
		createTableRequest.setKeySchema(Collections.singletonList(keySchemaElement));
		createTableRequest.setTableName(TABLE_NAME);
		
		amazonDynamoDB.createTable(createTableRequest);
		
		boolean tableIsCreated = false;
		long tableCreationTime = System.currentTimeMillis();
		while (System.currentTimeMillis()<tableCreationTime+TIME_TO_WAIT_FOR_TABLE_OPERATION_MILLISEC) {
			DescribeTableResult describeTableResult = amazonDynamoDB.describeTable(TABLE_NAME);
			if ("ACTIVE".equalsIgnoreCase(describeTableResult.getTable().getTableStatus())) {
				tableIsCreated=true;
				break;
			}
			Thread.sleep(1000L);
		}
		
		if (!tableIsCreated) {
			throw new RuntimeException("DynamoTable failed to create.");
		}
		
		logger.log(Level.INFO, "Table created after "+((System.currentTimeMillis()-tableCreationTime)/1000L)+ " seconds.");
		
		this.dynamoDbHelper = new DynamoDbHelper(TABLE_NAME);
	}
	
	private void deleteTable() throws Exception {
		DeleteTableRequest deleteTableRequest = new DeleteTableRequest();
		deleteTableRequest.setTableName(TABLE_NAME);

		amazonDynamoDB.deleteTable(deleteTableRequest);

		boolean tableIsDeleted = false;
		long tableDeletionTime = System.currentTimeMillis();
		while (System.currentTimeMillis()<tableDeletionTime+TIME_TO_WAIT_FOR_TABLE_OPERATION_MILLISEC) {
			try {
				DescribeTableResult describeTableResult = amazonDynamoDB.describeTable(TABLE_NAME);
				String status = describeTableResult.getTable().getTableStatus();
				if (! "DELETING".equalsIgnoreCase(status)) {
					throw new RuntimeException("Expected table to be in DELETING state but found "+status);
				}
			} catch (ResourceNotFoundException e) {
				tableIsDeleted=true;
				break;
			}
			Thread.sleep(1000L);
		}

		if (!tableIsDeleted) {
			throw new RuntimeException("DynamoTable failed to delete.");
		}
		
		logger.log(Level.INFO, "Table deleted after "+((System.currentTimeMillis()-tableDeletionTime)/1000L)+ " seconds.");
	
	}

	@After 
	public void tearDown() throws Exception {
		deleteTable();
	}

	@Ignore
	@Test
	public void testRoundTrip() {
		// create a record
		String userId = "some-user-id";
		String productCode = "some-product-code";
		String customerIdentifier = "some-customer-id";
		dynamoDbHelper.addMarketplaceId(userId, productCode, customerIdentifier);
		// retrieve the record
		String customerId = dynamoDbHelper.getMarketplaceCustomerIdForUser(userId);
		assertEquals(customerIdentifier, customerId);
		// retrieve a record that doesn't exist
		String notExistentId = dynamoDbHelper.getMarketplaceCustomerIdForUser("some-other-id");
		assertNull(notExistentId);
	}

}
