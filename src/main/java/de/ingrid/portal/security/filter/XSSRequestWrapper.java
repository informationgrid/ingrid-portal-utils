package de.ingrid.portal.security.filter;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import de.ingrid.portal.security.util.XSSUtil;
 
public class XSSRequestWrapper extends HttpServletRequestWrapper {

	/** Our helper for security operations ! */
	private XSSUtil xssUtil = null;

    /** Our Wrapper stripping the parameter values !
     * Pass XSSUtil instance with configuration.
     * @param servletRequest original request
     * @param xssUtil configuration, e.g. from FilterConfig etc.
     */
    public XSSRequestWrapper(HttpServletRequest servletRequest, XSSUtil xssUtil) {
        super(servletRequest);
        
        this.xssUtil = xssUtil;
    }

    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
    	return xssUtil.stripParameter(value, parameter);
    }

    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
    	return xssUtil.stripParameterValues(values, parameter);
    }
 
    @Override
	public Map getParameterMap() {
        Map origMap = super.getParameterMap();
    	return xssUtil.stripParameterMap(origMap);
    }

    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
    	return xssUtil.stripHeader(value, name);
    }
}
