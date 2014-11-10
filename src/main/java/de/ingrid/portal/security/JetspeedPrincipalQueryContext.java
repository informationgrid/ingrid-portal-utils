/*
 * **************************************************-
 * ingrid-portal-utils
 * ==================================================
 * Copyright (C) 2014 wemove digital solutions GmbH
 * ==================================================
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl5
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * **************************************************#
 */
/* 
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.ingrid.portal.security;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Principal query context. Simple hash map with convenient methods to put and
 * get casted types from the map.
 * 
 * 
 * @author <a href="mailto:joachim@wemove.com">Joachim Mueller</a>
 * 
 */
public class JetspeedPrincipalQueryContext extends HashMap<String, Object> {

	/** The serial version uid. */
	private static final long serialVersionUID = -7606523008399881258L;

	public static final String NAME_FILTER = "nameFilter";

	public static final String SECURITY_ATTRIBUTES = "securityAttributes";

	public static final String ASSOCIATED_ROLES = "associatedRoles";

	public static final String ASSOCIATED_GROUPS = "associatedGroups";

	public static final String ORDER = "order";

	public static final String OFFSET = "offset";

	public static final String LENGTH = "length";

	public static final String JETSPEED_PRINCIPAL_TYPE = "jetspeedPrincipalType";

	public static final String SECURITY_DOMAIN = "securityDomain";

	public JetspeedPrincipalQueryContext(String nameFilter, long offset, long length) {
		put(NAME_FILTER, nameFilter);
		put(OFFSET, Long.valueOf(offset));
		put(LENGTH, Long.valueOf(length));
	}

	public JetspeedPrincipalQueryContext(String nameFilter, long offset, long length, String order, List<String> roles,
			List<String> groups, List<String> users, Map<String, String> attributes) {
		put(NAME_FILTER, nameFilter);
		put(OFFSET, Long.valueOf(offset));
		put(LENGTH, Long.valueOf(length));
		put(ORDER, order);
		put(ASSOCIATED_ROLES, roles);
		put(ASSOCIATED_GROUPS, groups);
		put(SECURITY_ATTRIBUTES, attributes);
	}

	/**
	 * Return the filter for the principals name. The name can contain a
	 * wildcard at the right end.
	 * 
	 * @return the nameFilter
	 */
	public String getNameFilter() {
		return (String) this.get(NAME_FILTER);
	}

	/**
	 * Returns all security attributes for the principal. All security
	 * attributes MUST exist for the principal.
	 * 
	 * @return the securityAttributes
	 */
	@SuppressWarnings("unchecked")
	public Map<String, String> getSecurityAttributes() {
		return (Map<String, String>) this.get(SECURITY_ATTRIBUTES);
	}

	/**
	 * Returns all roles the principal must be member of.
	 * 
	 * @return the associatedRoles
	 */
	@SuppressWarnings("unchecked")
	public List<String> getAssociatedRoles() {
		return (List<String>) this.get(ASSOCIATED_ROLES);
	}

	/**
	 * Returns all groups the principal must be member of.
	 * 
	 * @return the associatedGroups
	 */
	@SuppressWarnings("unchecked")
	public List<String> getAssociatedGroups() {
		return (List<String>) this.get(ASSOCIATED_GROUPS);
	}

	/**
	 * Returns the sort order for the principals name. If it is 'desc' the
	 * principals are sorted backwards according to their names, all other
	 * values result in normal order.
	 * 
	 * @return the orderDesc
	 */
	public String getOrder() {
		return (String) this.get(ORDER);
	}

	/**
	 * @return the offset
	 */
	public Long getOffset() {
		return (Long) this.get(OFFSET);
	}

	/**
	 * @return the length
	 */
	public Long getLength() {
		return (Long) this.get(LENGTH);
	}

	/**
	 * @return the JetspeedPrincipalType name
	 */
	public String getJetspeedPrincipalType() {
		return (String) this.get(JETSPEED_PRINCIPAL_TYPE);
	}

	/**
	 * @return the security domain id
	 */
	public Long getSecurityDomain() {
		return (Long) this.get(SECURITY_DOMAIN);
	}

}
