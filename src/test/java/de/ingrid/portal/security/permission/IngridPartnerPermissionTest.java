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

public class IngridPartnerPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPartnerPermission.implies(Permission)'
     */
    public void testImpliesPermission() {
    	IngridPartnerPermission.Factory myPartnerPermissionFactory = new IngridPartnerPermission.Factory();
    	
        IngridPartnerPermission p = myPartnerPermissionFactory.newPermission("partner.he");
        IngridPartnerPermission p1 = myPartnerPermissionFactory.newPermission("partner.he");
        assertEquals(true, p.implies(p1));

        p = myPartnerPermissionFactory.newPermission("partner.*");
        p1 = myPartnerPermissionFactory.newPermission("partner.he");
        assertEquals(true, p.implies(p1));

        p = myPartnerPermissionFactory.newPermission("partner.he");
        p1 = myPartnerPermissionFactory.newPermission("partner.he.*");
        assertEquals(false, p.implies(p1));

        p = myPartnerPermissionFactory.newPermission("partner.he", "*");
        // use "edit" instead of "write" to have Jetspeed action ! (now Jetspeed Permission !)
        p1 = myPartnerPermissionFactory.newPermission("partner.he", "edit");
        assertEquals(true, p.implies(p1));

        p = myPartnerPermissionFactory.newPermission("partner.he", "*");
        p1 = myPartnerPermissionFactory.newPermission("partner.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getPartner());
        p = myPartnerPermissionFactory.newPermission("*", "*");
        assertEquals("*", p.getPartner());
        
    }

    public void testEqualsObject() {
    	IngridPartnerPermission.Factory myPartnerPermissionFactory = new IngridPartnerPermission.Factory();
        
    	IngridPartnerPermission p = myPartnerPermissionFactory.newPermission("partner.he", "view, edit");
    	IngridPartnerPermission p1 = myPartnerPermissionFactory.newPermission("partner.he", "*");
        assertEquals(true, p.equals(p1));       
    }
    
    public void testPermissionsAddBehaviour() {
    	IngridPartnerPermission.Factory myPartnerPermissionFactory = new IngridPartnerPermission.Factory();
    	IngridPermission.Factory myIngridPermissionFactory = new IngridPermission.Factory();

        Permissions ps = new Permissions();
        IngridPartnerPermission p = myPartnerPermissionFactory.newPermission("partner.he", "view, edit");
        ps.add(p);
        // NOTICE: REPLACES upper permission !
        p = myPartnerPermissionFactory.newPermission("partner.he", "view");
        ps.add(p);
        Enumeration en = ps.elements();
        int cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(1, cnt);
        assertEquals(false, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view, edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view")));
        assertEquals(false, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "edit")));

        p = myPartnerPermissionFactory.newPermission("partner.he", "view, edit");
        ps.add(p);
        
        // also add IngridPermission to collection ! stored separately cause different class !
        ps.add(myIngridPermissionFactory.newPermission("permission1", "view, edit"));
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(2, cnt);
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view,edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view")));

        assertEquals(true, ps.implies(myIngridPermissionFactory.newPermission("permission1", "view,edit")));
        assertEquals(true, ps.implies(myIngridPermissionFactory.newPermission("permission1", "edit")));
        assertEquals(true, ps.implies(myIngridPermissionFactory.newPermission("permission1", "view")));
        // new resource, nothing defined in collection, NO permission
        assertEquals(false, ps.implies(myPartnerPermissionFactory.newPermission("partner.ni", "view")));

        // top all allowed !
        p = myPartnerPermissionFactory.newPermission("*", "view, edit");
        assertEquals("*", p.getPartner());
        ps.add(p);
        // sub resources only view
        p = myPartnerPermissionFactory.newPermission("partner.he", "view");
        ps.add(p);
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(3, cnt);
        // sub resource no edit !
        assertEquals(false, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view,edit")));
        assertEquals(false, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view")));
        // but NEW sub resource all allowed cause top no restriction !
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("permission3", "view,edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("permission3", "edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("permission3", "view")));
    }

}
