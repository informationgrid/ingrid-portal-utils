package de.ingrid.portal.security.permission;

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
        p1 = new IngridPartnerPermission("partner.he", "write");
        assertEquals(true, p.implies(p1));

        p = new IngridPartnerPermission("partner.he", "*");
        p1 = new IngridPartnerPermission("partner.he", "");
        assertEquals(false, p.implies(p1));
        
        assertEquals("he", p.getPartner());
        p = new IngridPartnerPermission("*", "*");
        assertEquals("*", p.getPartner());
        
    }

}
