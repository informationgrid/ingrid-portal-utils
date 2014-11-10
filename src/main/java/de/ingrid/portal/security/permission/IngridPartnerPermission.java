/*
 * **************************************************-
 * ingrid-portal-utils
 * ==================================================
 * Copyright (C) 2014 wemove digital solutions GmbH
 * ==================================================
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl5
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * **************************************************#
 */
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

    /**
     * Constructor
     * 
     * @param partner
     *            The partner the permission applies for ('all' for all).
     * @param actions
     *            The actions for the permission (comma separated list).
     */
    public IngridPartnerPermission(String partner, String actions) {
        super(partner, actions);
    }

    /**
     * Constructor
     * 
     * @param partner
     */
    public IngridPartnerPermission(String partner) {
        super(partner, "*");
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
