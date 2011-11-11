/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.util;

import java.security.Permission;
import java.security.Permissions;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.jetspeed.security.PermissionManager;
import org.apache.jetspeed.security.Role;
import org.apache.jetspeed.security.RoleManager;
import org.apache.jetspeed.security.SecurityException;

/**
 * Security Helper class.
 *
 * @author joachim@wemove.com
 */
public class SecurityHelper {

    private final static Log log = LogFactory.getLog(SecurityHelper.class);
    
    /**
     * Merge role permissions with user permissions
     * 
     * @param p
     *            The Principal of the user to merge the role permission with.
     * @param permissionManager
     *            The JETSPEED permission manager.
     * @param roleManager
     *            The JETSPEED role manager.
     * @return The merged Permissions.
     */
    @SuppressWarnings("unchecked")
    public static Permissions getMergedPermissions(Principal p, PermissionManager permissionManager,
            RoleManager roleManager) {
        Permissions result = null;
        try {
            Collection<Role> roles = (Collection<Role>)roleManager.getRolesForUser(p.getName());
            result = getMergedPermissions(p, roles, permissionManager);
        } catch (SecurityException e) {
            if (log.isErrorEnabled()) {
                log.error("Error merging roles of principal '" + p.getName() + "'!", e);
            }
        }
        return result;
    }
    
    /**
     * Get merged permissions from user and his roles.
     * 
     * @param p
     * @param roles
     * @param permissionManager
     * @return
     */
    public static Permissions getMergedPermissions(Principal p, Collection<Role> roles, PermissionManager permissionManager) {
        
        Permissions result = null;
        Collection<Principal> principals = new ArrayList<Principal>();
        principals.add(p);
        Iterator<Role> roleIterator = roles.iterator();
        while (roleIterator.hasNext()) {
            // check for role based permission to show the user
            Role role = roleIterator.next();
            principals.add(role.getPrincipal());
        }
        result = permissionManager.getPermissions(principals);
        return result;        
    }
    
}
