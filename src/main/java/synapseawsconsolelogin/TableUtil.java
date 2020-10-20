package synapseawsconsolelogin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.sagebionetworks.client.SynapseClient;
import org.sagebionetworks.client.exceptions.SynapseException;
import org.sagebionetworks.client.exceptions.SynapseResultNotReadyException;
import org.sagebionetworks.repo.model.table.ColumnModel;
import org.sagebionetworks.repo.model.table.QueryResultBundle;
import org.sagebionetworks.repo.model.table.Row;
import org.sagebionetworks.repo.model.table.RowSet;
import org.sagebionetworks.repo.model.table.SelectColumn;

public class TableUtil {
	private static Logger logger = Logger.getLogger("TableUtil");

	private static final int QUERY_PARTS_MASK = 
			SynapseClient.QUERY_PARTMASK |
			SynapseClient.COUNT_PARTMASK |
			SynapseClient.COLUMNS_PARTMASK |
			SynapseClient.MAXROWS_PARTMASK;

	private static final String USER_ID = "userId";
	private static final String MARKETPLACE_CUSTOMER_ID = "marketplaceCustomerId";

	public static final long TABLE_UPDATE_TIMEOUT = 100000L;

	private SynapseClient synapseClient;

	public TableUtil(SynapseClient synapseClient) {
		this.synapseClient=synapseClient;
	}
	
	public String getMarketplaceCustomerIdForUser(String tableId, String userId) throws SynapseException, InterruptedException {
		String sql = "SELECT * FROM "+tableId+" WHERE "+USER_ID+" = "+userId;
		QueryResultBundle queryResult = executeQuery(sql, tableId, Integer.MAX_VALUE);
		List<SelectColumn> selectColumns = queryResult.getSelectColumns();
		RowSet rows = queryResult.getQueryResult().getQueryResults();

		int userIdIndex = getColumnIndexForName(selectColumns, USER_ID);
		int marketPlaceIdIndex = getColumnIndexForName(selectColumns, MARKETPLACE_CUSTOMER_ID);
		
		if (rows.getRows().size()>1) {
			throw new IllegalStateException("There are multiple AWS customer IDs for Synapse user "+userId);
		}
		
		if (rows.getRows().isEmpty()) {
			return null;
		}
		
		// there is exactly one result
		Row row = rows.getRows().get(0);
		
		List<String> values = row.getValues();
		String rowUser = values.get(userIdIndex);
		String marketplaceId = values.get(marketPlaceIdIndex);
		
		if (!userId.equals(rowUser)) {
			throw new IllegalStateException(rowUser+" is not "+userId);
		}
		
		return marketplaceId;
	}
	
	/*
	 * returns a list of SelectColumns for the given columnNames in the same order as
	 * said columnNames.
	 */
	public List<SelectColumn> createRowSetHeaders(String tableId, String[] columnNames) throws SynapseException  {
		List<SelectColumn> result = new ArrayList<SelectColumn>();
		List<ColumnModel> columns = synapseClient.getColumnModelsForTableEntity(tableId);
		for (String columnName : columnNames) {
			for (ColumnModel column : columns) {
				if (column.getName().equals(columnName)) {
					SelectColumn sc = new SelectColumn();
					sc.setColumnType(column.getColumnType());
					sc.setId(column.getId());
					sc.setName(columnName);
					result.add(sc);
					break;
				}
			}
		}
		if (result.size()<columnNames.length) throw new RuntimeException("Could not find columns for all column names.");
		return result;
	}

	public void addMarketplaceId(String tableId, String userId, String marketplaceId) throws SynapseException, InterruptedException {
		RowSet rowSet = new RowSet();
		rowSet.setTableId(tableId);
		String[] columnNames = new String[]{
				USER_ID,
				MARKETPLACE_CUSTOMER_ID};
		rowSet.setHeaders(createRowSetHeaders(tableId, columnNames));
		Row applicantProcessed = new Row();
		applicantProcessed.setValues(Arrays.asList(new String[]{
				userId,
				marketplaceId
		}));
		rowSet.setRows(Collections.singletonList(applicantProcessed));
		synapseClient.appendRowsToTable(rowSet, TABLE_UPDATE_TIMEOUT, tableId);

	}
	
	public static int getColumnIndexForName(List<SelectColumn> columns, String name)  {
		for (int i=0; i<columns.size(); i++) {
			if (columns.get(i).getName().equals(name)) return i;
		}
		List<String> names = new ArrayList<String>();
		for (SelectColumn column : columns) names.add(column.getName());
		throw new IllegalArgumentException("No column named "+name+". Available names: "+names);
	}
	
	
	/*
	 * Executes a query for which the max number of returned rows is known (i.e. we retrieve in a single page)
	 */
	private QueryResultBundle executeQuery(String sql, String tableId, long queryLimit) throws SynapseException, InterruptedException {
		String asyncJobToken = synapseClient.queryTableEntityBundleAsyncStart(sql, 0L, queryLimit, QUERY_PARTS_MASK, tableId);
		QueryResultBundle qrb=null;
		long backoff = 100L;
		for (int i=0; i<100; i++) {
			try {
				qrb = synapseClient.queryTableEntityBundleAsyncGet(asyncJobToken, tableId);
				break;
			} catch (SynapseResultNotReadyException e) {
				// keep waiting
				Thread.sleep(backoff);
				backoff *=2L;
			}
		}
		if (qrb==null) throw new RuntimeException("Query failed to return");
		List<Row> rows = qrb.getQueryResult().getQueryResults().getRows();
		if (qrb.getQueryCount()>rows.size()) throw new IllegalStateException(
				"Queried for "+queryLimit+" users but got back "+ rows.size()+" and total count: "+qrb.getQueryCount());
		return qrb;
	}
}
