package de.ingrid.portal.security.permission;

import junit.framework.TestCase;

public class IngridProviderPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridProviderPermission.implies(Permission)'
     */
    public void testImpliesPermission() {
        IngridProviderPermission p = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN, "he, bund");
        IngridProviderPermission p1 = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN, "he");
        assertEquals(true, p.implies(p1));

        p = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN + ".*", "he, bund");
        p1 = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "bund");
        assertEquals(true, p.implies(p1));

        p = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN_CONTENT + ".*", "he, bund");
        p1 = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN, "he, bund");
        assertEquals(false, p.implies(p1));

        p = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN + ".*", "he");
        p1 = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "he, bund");
        assertEquals(false, p.implies(p1));
        
        p = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN + ".*", "all");
        p1 = new IngridProviderPermission(IngridProviderPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "he, bund");
        assertEquals(true, p.implies(p1));
    }
}
