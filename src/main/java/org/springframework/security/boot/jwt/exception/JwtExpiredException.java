package org.springframework.security.boot.jwt.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class JwtExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>JwtExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public JwtExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>JwtExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public JwtExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
