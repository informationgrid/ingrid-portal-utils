/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.permission;

import java.security.Permission;

import org.apache.jetspeed.security.spi.PersistentJetspeedPermission;
import org.apache.jetspeed.security.spi.impl.JetspeedPermissionFactory;

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

    public static class Factory extends JetspeedPermissionFactory
    {
        public Factory() {
            super(INGRID_PARTNER_PERMISSION);
        }

        public IngridPartnerPermission newPermission(String name) {
            return new IngridPartnerPermission(getType(), name, "*");
        }

        public IngridPartnerPermission newPermission(String name, String actions) {
            return new IngridPartnerPermission(getType(), name, actions);
        }

        public IngridPartnerPermission newPermission(String name, int mask)
        {
            return new IngridPartnerPermission(getType(), name, mask);
        }

        public IngridPartnerPermission newPermission(PersistentJetspeedPermission permission)
        {
            if (permission.getType().equals(getType())) {
                return new IngridPartnerPermission(permission);
            }
            throw new IllegalArgumentException("Permission is not of type "+getType());
        }
    }

    /**
     * Constructor
     * 
     * @param partner
     *            The partner the permission applies for ('all' for all).
     * @param actions
     *            The actions for the permission (comma separated list).
     */
    protected IngridPartnerPermission(String type, String partner, String actions) {
        super(type, partner, actions);
    }

    protected IngridPartnerPermission(String type, String name, int mask) {
        super(type, name, mask);
    }

    protected IngridPartnerPermission(PersistentJetspeedPermission permission) {
        super(permission);
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
