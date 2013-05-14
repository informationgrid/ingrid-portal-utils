package de.ingrid.portal.security.filter;


import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import junit.framework.TestCase;
import de.ingrid.portal.security.util.XSSUtil;

public class XSSTest extends TestCase {
	
	/** Mocked FilterConfig containing regexps for external configuration ! */
	FilterConfig filterConfigMocked = null;

	/** The value the matching regular expressions will be replaced with ! */
	String confReplaceValue = "XSS_STRIPPED";

	/** Regular expressions passed from external configuration (web.xml). */
	String[] confRegexps = new String[] {
			"<script>(.*?)</script>",
			"src[\r\n]*=[\r\n]*\\\'(.*?)\\\'",
			"src[\r\n]*=[\r\n]*\\\"(.*?)\\\"",
			"</script>",
			"<script(.*?)>",
			"eval\\((.*?)\\)",
			"expression\\((.*?)\\)",
			"javascript:",
			"vbscript:",
			"onload(.*?)="
	};
	
	/** The "infected" XSS parameter values */
	String[] paramValuesInfected = new String[] {
			"<script>alert('TEST')</script>",
			"javascript:alert('TEST')",
			"alert('TEST')</script>",
			"<script>alert('TEST')",
			"eval('TEST')",
			"src=\"alert('TEST')\"",
			"expression('TEST')",
			"vbscript:alert('TEST')",
			"onload=alert('TEST')",
	};

	/** The CLEARED XSS parameter values ! $REPLACE_VALUE can be configured ! */
	String[] paramValuesStripped = new String[] {
			"$REPLACE_VALUE",
			"$REPLACE_VALUE" + "alert('TEST')",
			"alert('TEST')" + "$REPLACE_VALUE",
			"$REPLACE_VALUE" + "alert('TEST')",
			"$REPLACE_VALUE",
			"$REPLACE_VALUE",
			"$REPLACE_VALUE",
			"$REPLACE_VALUE" + "alert('TEST')",
			"$REPLACE_VALUE" + "alert('TEST')"
	};

	@Override
	protected void setUp() throws Exception {
		// mock FilterConfig

		// Map containing all filter params (regexps) for external configuration.
		Map<String, String> filterParamsMap = new HashMap<String, String>();
		// add replaceValue !
		filterParamsMap.put(XSSUtil.REPLACE_VALUE_PARAM_NAME, confReplaceValue);
		// add regular exprissions to be replaced by replaceValue !
		for (int i=0; i<confRegexps.length; i++) {
			String paramName = "param"+i;
			filterParamsMap.put(paramName, confRegexps[i]);
		}
		
		// mock FilterConfig (configuration from web.xml)
		filterConfigMocked = mock(FilterConfig.class);
		when(filterConfigMocked.getInitParameterNames()).thenReturn(Collections.enumeration(filterParamsMap.keySet()));
		for (String paramName: filterParamsMap.keySet()) {
			when(filterConfigMocked.getInitParameter(paramName)).thenReturn(filterParamsMap.get(paramName));
		}
	}

	public void testFilterConfig() throws ServletException {
		XSSUtil xssUtil = new XSSUtil();;
        xssUtil.parseFilterConfig(filterConfigMocked);

        assertEquals(this.confReplaceValue, xssUtil.getRegexReplaceValue());
        
		List<String> regexpsFromFilter = xssUtil.getRegexpFromConfig();
		for (int i=0; i<confRegexps.length; i++) {
			assertEquals(confRegexps[i], regexpsFromFilter.get(i));
		}
    }

	public void testXSSRequestWrapper() {
		// Map containing all "infected" XSS parameter
		Map<String, String> reqParamsMap = new HashMap<String, String>();
		for (int i=0; i<paramValuesInfected.length; i++) {
			String paramName = "param"+i;
			reqParamsMap.put(paramName, paramValuesInfected[i]);			
		}

		// mock request with infected parameters
		HttpServletRequest requestMocked = mock(HttpServletRequest.class);
		for (String paramName: reqParamsMap.keySet()) {
			when(requestMocked.getHeader(paramName)).thenReturn(reqParamsMap.get(paramName));
			when(requestMocked.getParameter(paramName)).thenReturn(reqParamsMap.get(paramName));
			when(requestMocked.getParameterValues(paramName)).thenReturn(new String[] { reqParamsMap.get(paramName) });
			when(requestMocked.getParameterMap()).thenReturn(reqParamsMap);
	    }

		// our request wrapper stripping values WITH DEFAULT CONFIGURATION !
		XSSUtil xssUtil = new XSSUtil();
		HttpServletRequestWrapper xssReq = new XSSRequestWrapper(requestMocked, xssUtil);		
		checkRequest(xssReq, xssUtil.getRegexReplaceValue());

		// our request wrapper stripping values WITH EXTERNAL CONFIGURATION !
		xssUtil.clear();
        xssUtil.parseFilterConfig(filterConfigMocked);
		xssReq = new XSSRequestWrapper(requestMocked, xssUtil);
		checkRequest(xssReq, confReplaceValue);
    }

	private void checkRequest(HttpServletRequestWrapper req, String replaceValue) {

		// all param values are stripped in request !
		for (int i=0; i<paramValuesStripped.length; i++) {
			String paramName = "param"+i;
			String paramValueStripped = paramValuesStripped[i].replace("$REPLACE_VALUE", replaceValue);

	        assertEquals(paramValueStripped, req.getHeader(paramName));
	        assertEquals(paramValueStripped, req.getParameter(paramName));
	        assertEquals(paramValueStripped, req.getParameterValues(paramName)[0]);
	        assertEquals(paramValueStripped, req.getParameterMap().get(paramName));
		}		
	}
}
