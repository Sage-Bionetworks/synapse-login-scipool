package synapseawsconsolelogin;

import java.util.Map;

public interface JWTClaimsExtractor {
	public Map<String,Object> extractClaims(String jwt);

}
