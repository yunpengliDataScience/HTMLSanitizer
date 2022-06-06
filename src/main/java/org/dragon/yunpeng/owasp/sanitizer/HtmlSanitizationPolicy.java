package org.dragon.yunpeng.owasp.sanitizer;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class HtmlSanitizationPolicy implements SanitizationPolicy {

    private PolicyFactory policyFactory;

    public HtmlSanitizationPolicy(String strictLevel) {
    	
    	if("STRICT".equals(strictLevel)) {
    		this.policyFactory = new HtmlPolicyBuilder().toFactory();
    		
    	}else if("ARTICLE".equals(strictLevel)) {
    		
    		this.policyFactory = Sanitizers.BLOCKS
    	            			.and(Sanitizers.FORMATTING)
    	            			.and(Sanitizers.STYLES)
    	            			.and(Sanitizers.IMAGES)
    	            			.and(Sanitizers.LINKS);
    	}else if("CUSTOM".equals(strictLevel)){
    		this.policyFactory = new HtmlPolicyBuilder().allowElements("my-element").toFactory();
    	}
        
    }

    @Override
    public String sanitize(String input) {
        return policyFactory.sanitize(input);
    }

}
