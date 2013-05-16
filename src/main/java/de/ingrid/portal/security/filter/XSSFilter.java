package de.ingrid.portal.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import de.ingrid.portal.security.util.XSSUtil;

public class XSSFilter implements Filter {

	private static final Logger LOG = Logger.getLogger(XSSFilter.class);
	
	/** Our helper for security operations ! */
	private XSSUtil xssUtil = new XSSUtil();

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (LOG.isInfoEnabled()) {
        	LOG.info("Initializing XSSFilter !");
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
            HttpServletRequest hreq = (HttpServletRequest) request;

    		if (LOG.isDebugEnabled()) {
        		xssUtil.debugRequest(hreq);
    		}

            if (isInvalid(hreq.getQueryString()) || isInvalid(hreq.getRequestURI()))
            {
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_BAD_REQUEST);
            }

            // DO NOT WRAP ! PROBLEMS WITH PORTAL LOGIN AFTERWARDS ! :(((((((((
            // So we can't process POST parameters !!!
//    		request = new XSSRequestWrapper(hreq, xssUtil);
        }

        chain.doFilter(request, response);
    }

    private boolean isInvalid(String value)
    {
    	if (value == null) {
    		return false;
    	}
    	
    	String decodedValue = xssUtil.urlDecode(value);

		if (xssUtil.containsXSS(decodedValue)) {
			return true;
		}
		
		return false;
    }

}