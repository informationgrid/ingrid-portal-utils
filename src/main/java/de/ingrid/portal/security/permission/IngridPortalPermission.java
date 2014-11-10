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

    public IngridPortalPermission(String name) {
        super(name, "*");
    }

    public IngridPortalPermission(String name, String actions) {
        super(name, actions);
    }
    
}
