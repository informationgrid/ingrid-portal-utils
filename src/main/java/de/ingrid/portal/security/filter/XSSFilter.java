package de.ingrid.portal.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import de.ingrid.portal.security.util.XSSUtil;

public class XSSFilter implements Filter {

	private static final Logger LOG = Logger.getLogger(XSSFilter.class);
	
	/** Our helper for security operations ! */
	private XSSUtil xssUtil = new XSSUtil();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (LOG.isDebugEnabled()) {
        	LOG.debug("Initializing XSSFilter !");
        }
        
        xssUtil.clear();
        xssUtil.parseFilterConfig(filterConfig);
    }
 
    @Override
    public void destroy() {
    }
 
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

    	if (request instanceof HttpServletRequest) {
    		request = new XSSRequestWrapper((HttpServletRequest) request, xssUtil);
        }

        chain.doFilter(request, response);
    }
}