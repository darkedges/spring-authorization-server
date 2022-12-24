package com.darkedges.privatekeyjwt.config;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {
	@EventListener
	public void onSuccess(AuthenticationSuccessEvent success) {
		System.out.println(success);
	}

	@EventListener
	public void onFailure(AbstractAuthenticationFailureEvent failures) {
		System.out.println(failures);
	}
}