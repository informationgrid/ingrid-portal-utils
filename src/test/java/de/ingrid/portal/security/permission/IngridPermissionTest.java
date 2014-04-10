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
        // NOTICE: REPLACES upper permission !
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
        assertEquals(true, ps.implies(new IngridPermission("permission2", "view")));
        assertEquals(false, ps.implies(new IngridPermission("permission2", "edit")));

        p = new IngridPermission("permission1", "view, edit");
        ps.add(p);
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(2, cnt);
        assertEquals(true, ps.implies(new IngridPermission("permission1", "view,edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "view")));
        // new resource, nothing defined, NO permission
        assertEquals(false, ps.implies(new IngridPermission("permission3", "view")));

        // top all allowed !
        p = new IngridPermission("*", "view, edit");
        ps.add(p);
        // sub resources only view
        p = new IngridPermission("permission1", "view");
        ps.add(p);
        p = new IngridPermission("permission2", "view");
        ps.add(p);
        en = ps.elements();
        cnt = 0;
        while (en.hasMoreElements()) {
            cnt++;
            en.nextElement();
        }
        assertEquals(3, cnt);
        // sub resources no edit !
        assertEquals(false, ps.implies(new IngridPermission("permission1", "edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission1", "view")));
        assertEquals(false, ps.implies(new IngridPermission("permission2", "edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission2", "view")));
        // but NEW sub resource all allowed cause no restriction in perms !
        assertEquals(true, ps.implies(new IngridPermission("permission3", "view,edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission3", "edit")));
        assertEquals(true, ps.implies(new IngridPermission("permission3", "view")));
    }

}
