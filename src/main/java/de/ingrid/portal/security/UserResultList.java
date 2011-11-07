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

import org.apache.jetspeed.security.User;
import org.apache.jetspeed.security.om.InternalUserPrincipal;

/**
 * Wrapper for a {@link JetspeedPrincipalResultList}. Takes care of casting to a {@link User}
 * typed result list.
 * 
 * 
 * @author <a href="mailto:joachim@wemove.com">Joachim Mueller</a>
 * 
 */
public class UserResultList extends JetspeedPrincipalResultList {

	/**
	 * Create a user result list from a JetspeedPrincipalResultList.
	 * 
	 * @param jprl
	 */
	public UserResultList(JetspeedPrincipalResultList jprl) {
		super(jprl.getResults(), jprl.getTotalSize());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.apache.jetspeed.security.JetspeedPrincipalResultList#getResults()
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<InternalUserPrincipal> getResults() {
		return (List<InternalUserPrincipal>) super.getResults();
	}

}
