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

public class IngridPartnerPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPartnerPermission.implies(Permission)'
     */
    public void testImpliesPermission() {
        IngridPartnerPermission p = new IngridPartnerPermission("partner.he");
        IngridPartnerPermission p1 = new IngridPartnerPermission("partner.he");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission("partner.*");
        p1 = new IngridPartnerPermission("partner.he");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission("partner.he");
        p1 = new IngridPartnerPermission("partner.he.*");
        assertEquals(false, p.implies(p1));

        p = new IngridPartnerPermission("partner.he", "*");
        p1 = new IngridPartnerPermission("partner.he", "write");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission("partner.he", "*");
        p1 = new IngridPartnerPermission("partner.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getPartner());
        p = new IngridPartnerPermission("*", "*");
        assertEquals("*", p.getPartner());
        
    }

}
