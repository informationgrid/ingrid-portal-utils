package de.ingrid.portal.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

public class XSSFilter implements Filter {

	private static final Logger LOG = Logger.getLogger(XSSFilter.class);

	/** Name of the parameter from filter config containing the value the
	 * matching regular expressions will be replaced with ! */
	public static final String REPLACE_VALUE_PARAM_NAME = "replaceValue";

	/** The value the matching regular expressions will be replaced with ! */
	String replaceValueFromConfig = null;

	/** The regular expressions which will be replaced by the replaceValue ! */
	List<String> regexpFromConfig = null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (LOG.isDebugEnabled()) {
        	LOG.debug("Initializing XSSFilter !");
        }

        // extract regexp from configuration
        if (filterConfig != null) {
        	List<String> myRegexps = new ArrayList<String>();

        	Enumeration paramNames = filterConfig.getInitParameterNames();
        	while (paramNames.hasMoreElements()) {
        		String paramName = paramNames.nextElement().toString();
        		String paramValue = filterConfig.getInitParameter(paramName);
        		
        		if (REPLACE_VALUE_PARAM_NAME.equals(paramName)) {
        			if (LOG.isDebugEnabled()) {
                    	LOG.debug("Passed replaceValue from web.xml: \"" + paramValue + "\"");
                    }

        			replaceValueFromConfig = paramValue;

        		} else {
                    if (LOG.isDebugEnabled()) {
                    	LOG.debug("Passed regex from web.xml: \"" + paramValue + "\"");
                    }

                    myRegexps.add(paramValue);
        		}
        	}
        	
        	if (myRegexps.size() > 0) {
        		regexpFromConfig = myRegexps;
        	}
        }
    }
 
    @Override
    public void destroy() {
    }
 
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        chain.doFilter(new XSSRequestWrapper((HttpServletRequest) request, regexpFromConfig, replaceValueFromConfig), response);
    }

	public List<String> getRegexpFromConfig() {
		return regexpFromConfig;
	}
	public String getReplaceValueFromConfig() {
		return replaceValueFromConfig;
	}
}