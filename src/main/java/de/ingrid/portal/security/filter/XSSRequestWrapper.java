package de.ingrid.portal.security.filter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.log4j.Logger;
 
public class XSSRequestWrapper extends HttpServletRequestWrapper {

	private static final Logger LOG = Logger.getLogger(XSSRequestWrapper.class);

	/** The default value the matching regular expressions will be replaced with ! */
    private String regexReplaceValue = "";

	/** The default regular expressions which will be replaced by the replaceValue ! */
    private Pattern[] patterns = new Pattern[]{
        // Script fragments
        Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
        // src='...'
        Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // lonely script tags
        Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // eval(...)
        Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // expression(...)
        Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // javascript:...
        Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
        // vbscript:...
        Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
        // onload(...)=...
        Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL)
    };
 
    /** Our Wrapper stripping the parameter values according to <b>DEFAULT configuration</b> (internal regexps).
     * @param servletRequest original request
     */
    public XSSRequestWrapper(HttpServletRequest servletRequest) {
        this(servletRequest, null, null);
    }

    /** Our Wrapper stripping the parameter values according to passed regexps and replaceValue !
     * @param servletRequest original request
     * @param regexps regular expressions to be replaced with default value.
     * 		Pass <b>null</b> if default configuration.
     * @param replaceValue The value the matching regular expressions will be replaced with.
     * 		Pass <b>null</b> if default configuration.
     */
    public XSSRequestWrapper(HttpServletRequest servletRequest, List<String> regexps, String replaceValue) {
        super(servletRequest);

        // value passed from config ?
        if (replaceValue != null) {
        	this.regexReplaceValue = replaceValue;
        }

        // set up patterns from configuration
        if (regexps != null) {
        	List<Pattern> myPatterns = new ArrayList<Pattern>();
        	
        	for (String regexp : regexps) {
        		myPatterns.add(
            		Pattern.compile(regexp, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL));        		
        	}
        	
        	if (myPatterns.size() > 0) {
        		this.patterns = myPatterns.toArray(new Pattern[myPatterns.size()]);
        	}
        }
    }
 
    @Override
    public String[] getParameterValues(String parameter) {
        String[] values = super.getParameterValues(parameter);
 
        if (values == null) {
            return null;
        }
 
        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = stripXSS(values[i]);
        }
 
        return encodedValues;
    }
 
    @Override
    public String getParameter(String parameter) {
        String value = super.getParameter(parameter);
 
        return stripXSS(value);
    }

    @Override
	public Map getParameterMap() {
        Map retMap = new HashMap();

        Map origMap = super.getParameterMap();
        Iterator it = origMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry)it.next();
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (value != null && String.class.isAssignableFrom(value.getClass())) {
            	value = stripXSS(value.toString());
            }
            
            retMap.put(key, value);
        }

        return retMap;
    }

    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return stripXSS(value);
    }
 
    private String stripXSS(String value) {
        if (value != null) {
        	String origValue = value;

            // NOTE: It's highly recommended to use the ESAPI library and uncomment the following line to
            // avoid encoded attacks.
        	// Needs huge ESAPI.properties file ! We skip this !
            //value = ESAPI.encoder().canonicalize(value);
 
            // Avoid null characters
            value = value.replaceAll("\0", "");
 
            // Remove all sections that match a pattern
            for (Pattern scriptPattern : patterns){
                value = scriptPattern.matcher(value).replaceAll(regexReplaceValue);
            }

            if (!origValue.equals(value)) {
            	LOG.warn("!!! Stripped request header/parameter value ");
            	LOG.warn("from \"" + origValue + "\"");
            	LOG.warn("to   \"" + value + "\"");
            }
        }

        return value;
    }
}
