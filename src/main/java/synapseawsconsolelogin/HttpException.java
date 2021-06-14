package synapseawsconsolelogin;

import org.apache.commons.lang.StringUtils;

public class HttpException extends RuntimeException {
	private int status;
	private String message;

	public HttpException(int status, String message, Throwable cause) {
		super(cause);
		this.status=status;
		this.message=message;
	}

	public int getStatus() {
		return status;
	}

	public String getMessage() {
		if (StringUtils.isEmpty(message)) {
			return super.getMessage();
		}
		return message;
	}


}
