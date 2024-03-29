/*
 * **************************************************-
 * ingrid-portal-utils
 * ==================================================
 * Copyright (C) 2014 - 2024 wemove digital solutions GmbH
 * ==================================================
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * https://joinup.ec.europa.eu/software/page/eupl
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

import org.apache.jetspeed.security.spi.PersistentJetspeedPermission;
import org.apache.jetspeed.security.spi.impl.JetspeedPermissionFactory;

/**
 * This class represent the portal permissions that are not further
 * restriced for partner or providers.
 * 
 * The permissions are i.e.
 * 
 *   portal.admin - for changing all aspects of the ingrid portal
 *   portal.admin.content - for changing all content in the portal (disclaimer, etc.)
 *
 * @author joachim@wemove.com
 */
public class IngridPortalPermission extends IngridPermission {

    private static final long serialVersionUID = 7405952399854216045L;

    private static final String INGRID_PORTAL_PERMISSION = "ingrid_portal";

    public static class Factory extends JetspeedPermissionFactory
    {
        public Factory() {
            super(INGRID_PORTAL_PERMISSION);
        }

        public IngridPortalPermission newPermission(String name) {
            return new IngridPortalPermission(getType(), name, "*");
        }

        public IngridPortalPermission newPermission(String name, String actions) {
            return new IngridPortalPermission(getType(), name, actions);
        }

        public IngridPortalPermission newPermission(String name, int mask)
        {
            return new IngridPortalPermission(getType(), name, mask);
        }

        public IngridPortalPermission newPermission(PersistentJetspeedPermission permission)
        {
            if (permission.getType().equals(getType())) {
                return new IngridPortalPermission(permission);
            }
            throw new IllegalArgumentException("Permission is not of type "+getType());
        }
    }

    protected IngridPortalPermission(String type, String provider, String actions) {
        super(type, provider, actions);
    }

    protected IngridPortalPermission(String type, String name, int mask) {
        super(type, name, mask);
    }

    protected IngridPortalPermission(PersistentJetspeedPermission permission) {
        super(permission);
    }
    
}
