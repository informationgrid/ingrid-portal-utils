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

import java.util.List;

import org.apache.jetspeed.security.om.InternalUserPrincipal;

/**
 * A container for principals that have been retrieved from storage with ranged
 * queries. Additional to the principals itself it also contains the total size
 * of the query result.
 * 
 * @author <a href="mailto:joachim@wemove.com">Joachim Mueller</a>
 * 
 */
public class JetspeedPrincipalResultList {

	private long totalSize = 0;

	private List<? extends InternalUserPrincipal> results = null;

	public JetspeedPrincipalResultList(List<? extends InternalUserPrincipal> results, long totalSize) {
		this.results = results;
		this.totalSize = totalSize;
	}

	/**
	 * Creates a result list, <em>totalSize</em> will be set to the lists size.
	 * 
	 * @param results
	 * @param firstResult
	 */
	public JetspeedPrincipalResultList(List<? extends InternalUserPrincipal> results) {
		this.results = results;
		this.totalSize = results.size();
	}

	/**
	 * Get the total size of search results. This can be higher than the number
	 * of returned principals.
	 * 
	 * @return
	 */
	public long getTotalSize() {
		return totalSize;
	}

	public void setTotalSize(long totalSize) {
		this.totalSize = totalSize;
	}

	/**
	 * Get the principal results.
	 * 
	 * @return
	 */
	public List<? extends InternalUserPrincipal> getResults() {
		return results;
	}
}
