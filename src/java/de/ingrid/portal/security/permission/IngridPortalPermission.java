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
        super(name, "");
    }

}
