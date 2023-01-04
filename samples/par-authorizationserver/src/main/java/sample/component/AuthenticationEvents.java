package sample.component;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {
	private final Log logger = LogFactory.getLog(getClass());
	@EventListener
	public void onSuccess(AuthenticationSuccessEvent success) {
		logger.debug(success);
	}

	@EventListener
	public void onFailure(AbstractAuthenticationFailureEvent failures) {
		logger.debug(failures);
	}
}
