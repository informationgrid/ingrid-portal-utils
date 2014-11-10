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
 * This class represent a responsibility permission for certain providers.
 * 
 * The permission name stands for a certain provider ('all' for all providers).
 * 
 * 'provider.he_lva' (resonsible for partner "Hessen", provider
 * "Landesvermessungsamt")
 * 
 * 'provider.ni_lva' (resonsible for partner "Niedersachsen", provider
 * "Landesvermessungsamt")
 * 
 * 'provider.*' (resonsible all providers)
 * 
 * 
 * Permission specific responsibilities can be achieved by using a hierarchical
 * permission name:
 * 
 * portal.admin.partner.provider.he_lva
 * 
 * portal.admin.partner.provider.ni_lva
 * 
 * @author joachim@wemove.com
 */
public class IngridProviderPermission extends IngridPermission {

    private static final long serialVersionUID = 7405952399854216041L;

    /**
     * Constructor
     * 
     * @param provider
     *            The providers name.
     * @param actions
     *            The providers actions (comma separated list)
     */
    public IngridProviderPermission(String provider, String actions) {
        super(provider, actions);
    }

    /**
     * Constructor
     * 
     * @param provider
     *            The providers name.
     */
    public IngridProviderPermission(String provider) {
        super(provider, "*");
    }

    /**
     * Return the provider of the permission. (last string before '.')
     * 
     * @return The provider.
     */
    public String getProvider() {
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
