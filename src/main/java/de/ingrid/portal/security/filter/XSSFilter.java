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

	List<String> regexpFromConfig = null;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (LOG.isDebugEnabled()) {
        	LOG.debug("Initializing XSSFilter !");
        }

        // extract regexp from configuration
        if (filterConfig != null) {
        	List<String> tmpRegexps = new ArrayList<String>();

        	Enumeration paramNames = filterConfig.getInitParameterNames();
        	while (paramNames.hasMoreElements()) {
        		String paramName = paramNames.nextElement().toString();
        		String tmpRegexp = filterConfig.getInitParameter(paramName);
        		
                if (LOG.isDebugEnabled()) {
                	LOG.debug("Passed regex from web.xml: \"" + tmpRegexp + "\"");
                }

                tmpRegexps.add(tmpRegexp);
        	}
        	
        	if (tmpRegexps.size() > 0) {
        		regexpFromConfig = tmpRegexps;
        	}
        }
    }
 
    @Override
    public void destroy() {
    }
 
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        chain.doFilter(new XSSRequestWrapper((HttpServletRequest) request, regexpFromConfig), response);
    }

	public List<String> getRegexpFromConfig() {
		return regexpFromConfig;
	}
}