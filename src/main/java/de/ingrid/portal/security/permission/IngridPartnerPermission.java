/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.permission;

import java.security.Permission;

/**
 * This class represent a responsibility permission for certain partner.
 * 
 * The permission name stands for a certain partner.
 * 
 * 'partner.he' (resonsible for partner "Hessen")
 * 
 * 'partner.ni' (resonsible for partner "Niedersachsen")
 * 
 * 'partner.*' (resonsible for all partners)
 * 
 * 
 * Permission specific responsibilities can be achieved by using a hierarchical
 * permission name:
 * 
 * portal.admin.partner.he (partner admin for "Hessen")
 * 
 * portal.admin.partner.ni (partner admin for "Niedersachsen")
 * 
 * @author joachim@wemove.com
 */
public class IngridPartnerPermission extends IngridPermission {

    private static final long serialVersionUID = 7405952399854216042L;

    private static final String INGRID_PARTNER_PERMISSION = "ingrid_partner";

    /**
     * Constructor
     * 
     * @param partner
     *            The partner the permission applies for ('all' for all).
     * @param actions
     *            The actions for the permission (comma separated list).
     */
    public IngridPartnerPermission(String partner, String actions) {
        super(INGRID_PARTNER_PERMISSION, partner, actions);
    }

    /**
     * Constructor
     * 
     * @param partner
     */
    public IngridPartnerPermission(String partner) {
        super(INGRID_PARTNER_PERMISSION, partner, "*");
    }

    /**
     * Return the partner (last string before '.')
     * 
     * @return The partner.
     */
    public String getPartner() {
        String name = this.getName();
        int pos = name.lastIndexOf('.');
        if (pos == -1) {
            return name;
        } else {
            return name.substring(name.lastIndexOf(".") + 1);
        }
    }

    /**
     * @see de.ingrid.portal.security.permission.IngridPermission#implies(java.security.Permission)
     */
    public boolean implies(Permission permission) {
        return super.implies(permission, true);
    }

}
