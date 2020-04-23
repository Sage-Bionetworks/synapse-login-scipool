package synapseawsconsolelogin;

import java.io.IOException;

/*
 * This is a simple abstraction around URL.openConnection() created to 
 * allow mocking in unit tests
 */
public interface HttpGetExecutor {
	/*
	 * Perform an HTTP GET at the given url
	 * and return the response body as a String
	 * 
	 * Anything other than a normal result (2xx status)
	 * is mapped to an exception
	 */
	String executeHttpGet(String url) throws IOException;
}
