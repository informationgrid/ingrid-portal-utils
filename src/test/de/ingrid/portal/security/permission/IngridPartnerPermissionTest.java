package de.ingrid.portal.security.permission;

import junit.framework.TestCase;

public class IngridPartnerPermissionTest extends TestCase {

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPartnerPermission.implies(Permission)'
     */
    public void testImpliesPermission() {
        IngridPartnerPermission p = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN, "he, bund");
        IngridPartnerPermission p1 = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN, "he");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN + ".*", "he, bund");
        p1 = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "bund");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN_CONTENT + ".*", "he, bund");
        p1 = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN, "he, bund");
        assertEquals(false, p.implies(p1));

        p = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN + ".*", "he");
        p1 = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "he, bund");
        assertEquals(false, p.implies(p1));
        
        p = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN + ".*", "all");
        p1 = new IngridPartnerPermission(IngridPartnerPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "he, bund");
        assertEquals(true, p.implies(p1));
        
    }

}
