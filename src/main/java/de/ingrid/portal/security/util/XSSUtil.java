package de.ingrid.portal.security.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.FilterConfig;

import org.apache.log4j.Logger;



/** Utility class for XSS security operations !
 * NO singleton, use instance to avoid problems with multithreading ! 
 */
public class XSSUtil {

	private static final Logger LOG = Logger.getLogger(XSSUtil.class);

	/** Name of the parameter from filter config containing the value the
	 * matching regular expressions will be replaced with ! */
	public static final String REPLACE_VALUE_PARAM_NAME = "replaceValue";

	/** The value the matching regular expressions will be replaced with ! */
    private String regexReplaceValue = "";

	/** The regular expressions from filter configuration. */
	List<String> regexpFromConfig = new ArrayList<String>();

	/** Our patterns (regexps) to be matched and replaced ! */
	List<Pattern> patterns = new ArrayList<Pattern>();

	/** The default patterns (regexps) which will be used if no configuration from filter ! */
    private Pattern[] defaultPatterns = new Pattern[]{
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
 
	/** Default configuration -> matching internal regexps will be replaced by ""  ! */
	public XSSUtil() {
		clear();
	}

	/** Return to default state clearing all encapsulated values, states ... */
	public void clear() {
		this.regexReplaceValue = "";
		this.regexpFromConfig = new ArrayList<String>();
		this.patterns = Arrays.asList(defaultPatterns);
	}

	/** Extract parameters from filter configuration (initial parameters passed from web.xml).
	 * NOTICE: Keeps current configuration if no regexps passed from filterconfig ! */
	public void parseFilterConfig(FilterConfig filterConfig) {
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

        			setRegexReplaceValue(paramValue);

        		} else {
                    if (LOG.isDebugEnabled()) {
                    	LOG.debug("Passed regex from web.xml: \"" + paramValue + "\"");
                    }

                    myRegexps.add(paramValue);
        		}
        	}
        	
            // set up patterns from configuration
        	if (myRegexps.size() > 0) {
        		regexpFromConfig = myRegexps;

        		this.patterns = new ArrayList<Pattern>();
            	for (String regexp : myRegexps) {
            		this.patterns.add(
                		Pattern.compile(regexp, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL));        		
            	}
        	}
        }
	}

    /** Clear value from malicious code.
     * @param values "infected" value
     * @return cleared value
     */
    public String stripParameter(String value) {
        return stripXSS(value);
    }

    /** Clear values from malicious code.
     * @param values "infected" values
     * @return cleared values
     */
    public String[] stripParameterValues(String[] values) {
        if (values == null) {
            return null;
        }
 
        int count = values.length;
        String[] encodedValues = new String[count];
        for (int i = 0; i < count; i++) {
            encodedValues[i] = stripParameter(values[i]);
        }
 
        return encodedValues;
    }

    /** Clear values in map from malicious code.
     * @param origMap parameter map from request with "infected" values
     * @return cleared parameter map
     */
    public Map stripParameterMap(Map origMap) {
        Map retMap = new HashMap();

        Iterator it = origMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry)it.next();
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (value != null && String.class.isAssignableFrom(value.getClass())) {
            	value = stripParameter(value.toString());
            }
            
            retMap.put(key, value);
        }

        return retMap;
    }

    /** Clear the given "infected" value. */
    private String stripXSS(String value) {
    	if (value == null) {
            return null;    		
    	}

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

        return value;
    }

	/** Get the value the matching regular expressions will be replaced with ! */
	public String getRegexReplaceValue() {
		return regexReplaceValue;
	}

	/** Set the value the matching regular expressions will be replaced with ! */
	public void setRegexReplaceValue(String regexReplaceValue) {
		this.regexReplaceValue = regexReplaceValue;
	}

	/** Just for Unit tests to check read regexps ! */
	public List<String> getRegexpFromConfig() {
		return regexpFromConfig;
	}
}
