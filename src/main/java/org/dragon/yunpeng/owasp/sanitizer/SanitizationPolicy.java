package org.dragon.yunpeng.owasp.sanitizer;

public interface SanitizationPolicy {

	/**
	 * Sanitizes the string according to the policy
	 * 
	 * @param input the input string to be sanitized
	 * @return the sanitized string
	 */
	String sanitize(String input);

}
