package synapseawsconsolelogin;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;


public class DynamoDbHelper {
	
	private static final String USER_ID = "userId";
	private static final String PRODUCT_CODE = "productCode";
	private static final String CUSTOMER_ID = "marketplaceCustomerId";
	
	private AmazonDynamoDB amazonDynamoDB;
	
	private static final List<String> ATTRIBUTES_TO_RETRIEVE = Arrays.asList(PRODUCT_CODE, CUSTOMER_ID);
	
	private String tableName;

	public DynamoDbHelper(String tableName, AmazonDynamoDB amazonDynamoDB) {
		this.amazonDynamoDB = amazonDynamoDB;
		this.tableName = tableName;
	}
	
	public DynamoDbHelper(String tableName) {
		this(tableName, AmazonDynamoDBClientBuilder.defaultClient());
	}
	
	private static AttributeValue stringAttributeValue(String s) {
		AttributeValue attributeValue = new AttributeValue();
		attributeValue.setS(s);
		return attributeValue;
	}
	
	public String getMarketplaceCustomerIdForUser(String userId) {
		GetItemRequest getItemRequest = new GetItemRequest();
		getItemRequest.setTableName(tableName);
		Map<String,AttributeValue> key = new HashMap<String,AttributeValue>();
		AttributeValue keyValue = stringAttributeValue(userId);
		key.put(USER_ID, keyValue);
		getItemRequest.setKey(key);
		getItemRequest.setAttributesToGet(ATTRIBUTES_TO_RETRIEVE);
		getItemRequest.setConsistentRead(true);
		GetItemResult getItemResult = amazonDynamoDB.getItem(getItemRequest);
		Map<String, AttributeValue> results = getItemResult.getItem();
		if (results==null || !results.containsKey(CUSTOMER_ID)) {
			return null;
		}
		AttributeValue attributeValue = results.get(CUSTOMER_ID);
		return attributeValue.getS();
	}
	
	public void addMarketplaceId(String userId, String productCode, String customerIdentifier) {
		PutItemRequest putItemRequest = new PutItemRequest();
		Map<String, AttributeValue> newRecord = new HashMap<String, AttributeValue>();
		newRecord.put(USER_ID, stringAttributeValue(userId));
		newRecord.put(PRODUCT_CODE, stringAttributeValue(productCode));
		newRecord.put(CUSTOMER_ID, stringAttributeValue(customerIdentifier));
		putItemRequest.setItem(newRecord);
		putItemRequest.setTableName(tableName);
		amazonDynamoDB.putItem(putItemRequest);
	}


}
