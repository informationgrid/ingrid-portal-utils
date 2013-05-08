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

    private static Pattern[] patterns = new Pattern[]{
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
        this(servletRequest, null);
    }

    /** Our Wrapper stripping the parameter values according to passed regexps !
     * @param servletRequest original request
     * @param regexpsFromConfig configuration of filter from web.xml (initial parameters).<br>
     * 		Pass <b>null</b> if default configuration.<br>
     * 		Pass regexps to configure stripping ! 
     */
    public XSSRequestWrapper(HttpServletRequest servletRequest, List<String> regexpsFromConfig) {
        super(servletRequest);

        // set up patterns from configuration
        if (regexpsFromConfig != null) {
        	List<Pattern> tmpPatterns = new ArrayList<Pattern>();
        	
        	for (String regexp : regexpsFromConfig) {
        		tmpPatterns.add(
            		Pattern.compile(regexp, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL));        		
        	}
        	
        	if (tmpPatterns.size() > 0) {
        		patterns = tmpPatterns.toArray(new Pattern[tmpPatterns.size()]);
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
                value = scriptPattern.matcher(value).replaceAll("");
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
