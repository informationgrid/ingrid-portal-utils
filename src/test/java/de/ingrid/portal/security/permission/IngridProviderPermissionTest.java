package de.ingrid.portal.security.permission;

import java.security.Permissions;
import java.util.Enumeration;

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
        // use "edit" instead of "write" to have Jetspeed action ! (now Jetspeed Permission !)
        p1 = new IngridProviderPermission("provider.he", "edit");
        assertEquals(true, p.implies(p1));

        p = new IngridProviderPermission("provider.he", "*");
        p1 = new IngridProviderPermission("provider.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getProvider());
        p = new IngridProviderPermission("*", "*");
        assertEquals("*", p.getProvider());
    }

    public void testPermissionsAddBehaviour() {
        
        Permissions ps = new Permissions();
        IngridProviderPermission p = new IngridProviderPermission("provider.he", "view, edit");
        ps.add(p);
        // NOTICE: REPLACES upper permission !
        p = new IngridProviderPermission("provider.he", "view");
        ps.add(p);
        p = new IngridProviderPermission("provider.he", "view");
        ps.add(p);
        Enumeration en = ps.elements();
        int cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(1, cnt);
        assertEquals(false, ps.implies(new IngridProviderPermission("provider.he", "view, edit")));
        assertEquals(true, ps.implies(new IngridProviderPermission("provider.he", "view")));
        assertEquals(true, ps.implies(new IngridProviderPermission("provider.he", "view")));
        assertEquals(false, ps.implies(new IngridProviderPermission("provider.he", "edit")));

        p = new IngridProviderPermission("provider.he", "view, edit");
        ps.add(p);

        // also IngridPartnerPermission !
        ps.add(new IngridPartnerPermission("partner.he", "view, edit"));
        
        // also IngridPermission !
        ps.add(new IngridPermission("permission1", "view, edit"));
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(3, cnt);
        assertEquals(true, ps.implies(new IngridProviderPermission("provider.he", "view,edit")));
        assertEquals(true, ps.implies(new IngridProviderPermission("provider.he", "edit")));
        assertEquals(true, ps.implies(new IngridProviderPermission("provider.he", "view")));

        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "view,edit")));
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "edit")));
        assertEquals(true, ps.implies(new IngridPartnerPermission("partner.he", "view")));

        assertEquals(true, ps.implies(new IngridPermission("permission1", "view,edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "view")));
    }


}
