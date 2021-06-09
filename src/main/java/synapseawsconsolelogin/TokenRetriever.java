package synapseawsconsolelogin;

public interface TokenRetriever {

		public IdAndAccessToken getTokens(String redirectUrl, String authorizationCode);

}
