package de.ingrid.portal.security.permission;

import java.security.Permissions;
import java.util.Enumeration;

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
        // use "edit" instead of "write" to have Jetspeed action ! (now Jetspeed Permission !)
        p1 = new IngridPartnerPermission("partner.he", "edit");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission("partner.he", "*");
        p1 = new IngridPartnerPermission("partner.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getPartner());
        p = new IngridPartnerPermission("*", "*");
        assertEquals("*", p.getPartner());
        
    }

    public void testPermissionsAddBehaviour() {
        
        Permissions ps = new Permissions();
        IngridPartnerPermission p = new IngridPartnerPermission("partner.he", "view, edit");
        ps.add(p);
        // NOTICE: REPLACES upper permission !
        p = new IngridPartnerPermission("partner.he", "view");
        ps.add(p);
        p = new IngridPartnerPermission("partner.he", "view");
        ps.add(p);
        Enumeration en = ps.elements();
        int cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(1, cnt);
        assertEquals(false, ps.implies(new IngridPartnerPermission("partner.he", "view, edit")));
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "view")));
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "view")));
        assertEquals(false, ps.implies(new IngridPartnerPermission("partner.he", "edit")));

        p = new IngridPartnerPermission("partner.he", "view, edit");
        ps.add(p);
        
        // also IngridPermission !
        ps.add(new IngridPermission("permission1", "view, edit"));
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(2, cnt);
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "view,edit")));
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "edit")));
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "view")));

        assertEquals(true, ps.implies(new IngridPermission("permission1", "view,edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "view")));
    }

}
