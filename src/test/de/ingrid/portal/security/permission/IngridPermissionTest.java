package de.ingrid.portal.security.permission;

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
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "view");
        assertEquals(true, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_CONTENT + ".*", "view, edit");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN + ".*", "view");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_CONTENT, "view, edit");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        assertEquals(false, p.implies(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "");
        p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view");
        assertEquals(false, p.implies(p1));
        
    }

    /*
     * Test method for 'de.ingrid.portal.security.permission.IngridPermission.equals(Object)'
     */
    public void testEqualsObject() {
        
        IngridPermission p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        IngridPermission p1 = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN, "view, edit");
        assertEquals(true, p.equals(p1));

        p = new IngridPermission(IngridPermission.PERMISSION_PORTAL_ADMIN_CONTENT + ".*", "view, edit");
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

}
