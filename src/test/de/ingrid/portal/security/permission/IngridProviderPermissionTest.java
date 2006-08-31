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
