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

import java.security.Permissions;
import java.util.Enumeration;

import junit.framework.TestCase;

public class IngridPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPermission.getActions()'
     */
    public void testGetActions() {
        IngridPermission p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        assertEquals("view, edit", p.getActions());
    }

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPermission.implies(Permission)'
     */
    public void testImpliesPermission() {
        IngridPermission p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        IngridPermission p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(true, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN + ".*", "view, edit");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_PARTNER, "view");
        assertEquals(true, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_PARTNER + ".*", "view, edit");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN + ".*", "view");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_PARTNER, "view, edit");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(false, p.implies(p1));
        
        p = new IngridPermission("*", "");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "*");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(true, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "*");
        assertEquals(false, p.implies(p1));
    }

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPermission.equals(Object)'
     */
    public void testEqualsObject() {
        
        IngridPermission p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        IngridPermission p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        assertEquals(true, p.equals(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_PARTNER + ".*", "view, edit");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        assertEquals(false, p.equals(p1));
        
        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(false, p.equals(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        assertEquals(true, p.equals(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        assertEquals(false, p.equals(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(false, p.equals(p1));
        
    }
    
    public void testPermissionsAddBehaviour() {
        
        Permissions ps = new Permissions();
        IngridPermission p = new IngridPermission("permission1", "view, edit");
        ps.add(p);
        p = new IngridPermission("permission1", "view");
        ps.add(p);
        p = new IngridPermission("permission2", "view");
        ps.add(p);
        Enumeration en = ps.elements();
        int cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(2, cnt);
        assertEquals(false, ps.implies(new IngridPermission("permission1", "view, edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "view")));
    }

}
