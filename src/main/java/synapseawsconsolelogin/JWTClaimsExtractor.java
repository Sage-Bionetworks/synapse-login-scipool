package synapseawsconsolelogin;

import io.jsonwebtoken.Claims;

public interface JWTClaimsExtractor {
	public Claims extractClaims(String jwt);

}
