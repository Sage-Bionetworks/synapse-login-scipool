package synapseawsconsolelogin;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.amazonaws.services.marketplacemetering.AWSMarketplaceMetering;
import com.amazonaws.services.marketplacemetering.AWSMarketplaceMeteringClientBuilder;
import com.amazonaws.services.marketplacemetering.model.ResolveCustomerRequest;
import com.amazonaws.services.marketplacemetering.model.ResolveCustomerResult;

public class MarketplaceMeteringHelper {
	private static Logger logger = Logger.getLogger("MarketplaceMeteringHelper");

	private AWSMarketplaceMetering client;

	public MarketplaceMeteringHelper() {
		this.client = AWSMarketplaceMeteringClientBuilder.defaultClient();
	}
	
	/*
	 * Call the Marketplace Metering service to exchange a marketplace token for a product code and customer id
	 * Details of the service are here:
	 * https://docs.aws.amazon.com/marketplacemetering/latest/APIReference/API_ResolveCustomer.html
	 */
	ResolveCustomerResult resolveCustomer(String awsMarketplaceToken) {
		ResolveCustomerRequest resolveCustomerRequest = new ResolveCustomerRequest();
		resolveCustomerRequest.setRegistrationToken(awsMarketplaceToken);
		ResolveCustomerResult resolveCustomerResult = client.resolveCustomer(resolveCustomerRequest);
		logger.log(Level.INFO, "resolveCustomerResult: "+resolveCustomerResult);
		return resolveCustomerResult;
	}

}
