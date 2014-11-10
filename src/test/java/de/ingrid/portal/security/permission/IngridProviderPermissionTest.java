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
package de.ingrid.portal.security.permission;

import junit.framework.TestCase;

public class IngridProviderPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridProviderPermission.implies(Permission)'
     */
    public void testImpliesPermission() {

        IngridProviderPermission p = new IngridProviderPermission("provider.he");
        IngridProviderPermission p1 = new IngridProviderPermission("provider.he");
        assertEquals(true, p.implies(p1));

        p = new IngridProviderPermission("provider.*");
        p1 = new IngridProviderPermission("provider.he");
        assertEquals(true, p.implies(p1));

        p = new IngridProviderPermission("provider.he");
        p1 = new IngridProviderPermission("provider.he.*");
        assertEquals(false, p.implies(p1));

        p = new IngridProviderPermission("provider.he", "*");
        p1 = new IngridProviderPermission("provider.he", "write");
        assertEquals(true, p.implies(p1));

        p = new IngridProviderPermission("provider.he", "*");
        p1 = new IngridProviderPermission("provider.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getProvider());
        p = new IngridProviderPermission("*", "*");
        assertEquals("*", p.getProvider());
    }
}
