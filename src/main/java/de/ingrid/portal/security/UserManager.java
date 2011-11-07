/* Copyright 2004 Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

import org.apache.jetspeed.security.SecurityException;
import org.apache.jetspeed.security.User;

/**
 * <p>
 * Extends UserManager to provide better query functionality.
 * </p>
 * 
 */
public interface UserManager extends org.apache.jetspeed.security.UserManager
{

    /**
     * <p>
     * Retrieves a detached and modifiable {@link User} list matching the corresponding
     * query context. It returns a {@link UserResultList}, containing
     * the actual result list an the total number of results from the query.
     * 
     * </p>
     * 
     * @param queryContext The (@see JetspeedPrincipalQueryContext) for this query.
     * @return
     * @throws SecurityException
     */
    public UserResultList getUsersExtended(JetspeedPrincipalQueryContext queryContext) throws SecurityException;   
    

}