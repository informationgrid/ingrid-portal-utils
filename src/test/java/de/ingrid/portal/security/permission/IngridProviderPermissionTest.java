package de.ingrid.portal.security.permission;

import java.security.Permissions;
import java.util.Enumeration;

import junit.framework.TestCase;

public class IngridProviderPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridProviderPermission.implies(Permission)'
     */
    public void testImpliesPermission() {
    	IngridProviderPermission.Factory myProviderPermissionFactory = new IngridProviderPermission.Factory();

        IngridProviderPermission p = myProviderPermissionFactory.newPermission("provider.he");
        IngridProviderPermission p1 = myProviderPermissionFactory.newPermission("provider.he");
        assertEquals(true, p.implies(p1));

        p = myProviderPermissionFactory.newPermission("provider.*");
        p1 = myProviderPermissionFactory.newPermission("provider.he");
        assertEquals(true, p.implies(p1));

        p = myProviderPermissionFactory.newPermission("provider.he");
        p1 = myProviderPermissionFactory.newPermission("provider.he.*");
        assertEquals(false, p.implies(p1));

        p = myProviderPermissionFactory.newPermission("provider.he", "*");
        // use "edit" instead of "write" to have Jetspeed action ! (now Jetspeed Permission !)
        p1 = myProviderPermissionFactory.newPermission("provider.he", "edit");
        assertEquals(true, p.implies(p1));

        p = myProviderPermissionFactory.newPermission("provider.he", "*");
        p1 = myProviderPermissionFactory.newPermission("provider.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getProvider());
        p = myProviderPermissionFactory.newPermission("*", "*");
        assertEquals("*", p.getProvider());
    }

    public void testEqualsObject() {
    	IngridProviderPermission.Factory myProviderPermissionFactory = new IngridProviderPermission.Factory();
        
    	IngridProviderPermission p = myProviderPermissionFactory.newPermission("provider.he", "view, edit");
    	IngridProviderPermission p1 = myProviderPermissionFactory.newPermission("provider.he", "*");
        assertEquals(true, p.equals(p1));       
    }
    
    public void testPermissionsAddBehaviour() {
    	IngridProviderPermission.Factory myProviderPermissionFactory = new IngridProviderPermission.Factory();
    	IngridPartnerPermission.Factory myPartnerPermissionFactory = new IngridPartnerPermission.Factory();
    	IngridPermission.Factory myIngridPermissionFactory = new IngridPermission.Factory();

        Permissions ps = new Permissions();
        IngridProviderPermission p = myProviderPermissionFactory.newPermission("provider.he", "view, edit");
        ps.add(p);
        // NOTICE: REPLACES upper permission !
        p = myProviderPermissionFactory.newPermission("provider.he", "view");
        ps.add(p);
        Enumeration en = ps.elements();
        int cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(1, cnt);
        assertEquals(false, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "view, edit")));
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "view")));
        assertEquals(false, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "edit")));

        // NOTICE: REPLACES upper permission !
        p = myProviderPermissionFactory.newPermission("provider.he", "view, edit");
        ps.add(p);

        // also IngridPartnerPermission !
        ps.add(myPartnerPermissionFactory.newPermission("partner.he", "view, edit"));
        
        // also IngridPermission !
        ps.add(myIngridPermissionFactory.newPermission("permission1", "view, edit"));
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(3, cnt);
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "view,edit")));
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "edit")));
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "view")));

        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view,edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "edit")));
        assertEquals(true, ps.implies(myPartnerPermissionFactory.newPermission("partner.he", "view")));

        assertEquals(true, ps.implies(myIngridPermissionFactory.newPermission("permission1", "view,edit")));
        assertEquals(true, ps.implies(myIngridPermissionFactory.newPermission("permission1", "edit")));
        assertEquals(true, ps.implies(myIngridPermissionFactory.newPermission("permission1", "view")));
        // new resource, nothing defined, NO permission
        assertEquals(false, ps.implies(myProviderPermissionFactory.newPermission("provider.ni", "view")));

        // top all allowed !
        p = myProviderPermissionFactory.newPermission("*", "view, edit");
        assertEquals("*", p.getProvider());
        ps.add(p);
        // sub resources only view
        p = myProviderPermissionFactory.newPermission("provider.he", "view");
        ps.add(p);
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(4, cnt);
        // sub resource no edit !
        assertEquals(false, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "view,edit")));
        assertEquals(false, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "edit")));
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.he", "view")));
        // but NEW sub resource all allowed cause top no restriction !
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.ni", "view,edit")));
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.ni", "edit")));
        assertEquals(true, ps.implies(myProviderPermissionFactory.newPermission("provider.ni", "view")));

    }
}
