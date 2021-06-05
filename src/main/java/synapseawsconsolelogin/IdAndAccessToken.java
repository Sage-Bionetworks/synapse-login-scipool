package synapseawsconsolelogin;

import org.scribe.model.Token;

public class IdAndAccessToken {
	private Token idToken;
	private Token accessToken;
	
	public IdAndAccessToken(Token idToken, Token accessToken) {
		super();
		this.idToken = idToken;
		this.accessToken = accessToken;
	}

	public Token getIdToken() {
		return idToken;
	}

	public void setIdToken(Token idToken) {
		this.idToken = idToken;
	}

	public Token getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(Token accessToken) {
		this.accessToken = accessToken;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((accessToken == null) ? 0 : accessToken.hashCode());
		result = prime * result + ((idToken == null) ? 0 : idToken.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		IdAndAccessToken other = (IdAndAccessToken) obj;
		if (accessToken == null) {
			if (other.accessToken != null)
				return false;
		} else if (!accessToken.equals(other.accessToken))
			return false;
		if (idToken == null) {
			if (other.idToken != null)
				return false;
		} else if (!idToken.equals(other.idToken))
			return false;
		return true;
	}


}
