/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.permission;

import java.security.BasicPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.jetspeed.security.spi.impl.BaseJetspeedPermission;

/**
 * General Ingrid permission class. Represents a permission with the parameter 
 * name and actions. Provides basic permission methods.<br>
 * NOTICE: This is now a Jetspeed permission of type "ingrid", or subtypes "ingrid_partner", "ingrid_provider" !
 * Extends now BaseJetspeedPermission and NOT BasicPermission ! But behaviour is like BasicPermission !
 *
 * @author joachim@wemove.com
 */
public class IngridPermission extends BaseJetspeedPermission {

    /** Simulate BasicPermissionCollection ! This one is returned when collection for this permission is requested ! */
    private static class IngridPermissionCollection extends PermissionCollection
    {
		private transient Map<String, Permission> perms;

        public IngridPermissionCollection() {
            perms = new HashMap<String, Permission>(11);
        }

        @Override
        public void add(Permission permission) {
            synchronized (this) {
                perms.put(permission.getName(), permission);
            }
        }

        @Override
        public Enumeration<Permission> elements() {
            synchronized (this) {
                return Collections.enumeration(perms.values());
            }
        }

        @Override
        public boolean implies(Permission permission) {
            // strategy:
            // Check for full match first. Then work our way up the
            // path looking for matches on a.b..*

            String path = permission.getName();
            Permission x;

            synchronized (this) {
                x = perms.get(path);
            }

            if (x != null) {
                // we have a direct hit!
                return x.implies(permission);
            }

            // work our way up the tree...
            int last, offset;

            offset = path.length()-1;

            while ((last = path.lastIndexOf(".", offset)) != -1) {
                path = path.substring(0, last+1) + "*";
                //System.out.println("check "+path);

                synchronized (this) {
                    x = perms.get(path);
                }

                if (x != null) {
                    return x.implies(permission);
                }
                offset = last -1;
            }

            // check for "*"
            synchronized (this) {
                x = perms.get("*");
            }
            if (x != null) {
                return x.implies(permission);
            }
            
            return false;
        }
    }

	private static final long serialVersionUID = 2246210603932755952L;
    
    private static final String INGRID_PERMISSION = "ingrid";

    /** encapsulated BasicPermission used for handling of name ! */
    protected BasicPermission myBasicPermission = null;
    
    // permission to change all portal specific stuff
    public static String PERMISSION_PORTAL_ADMIN = "admin.portal";
    // permission to admin the users of a certain partner
    public static String PERMISSION_PORTAL_ADMIN_PARTNER = "admin.portal.partner";
    // permission to admin the users of a certain provider
    public static String PERMISSION_PORTAL_ADMIN_PROVIDER = "admin.portal.provider";

    // permission to change the search engine index (urls, start, stop)
    public static String PERMISSION_PORTAL_ADMIN_INDEX = "admin.portal.partner.provider.index";
    // permission to change the search engine index (catalog topics, measure, service)
    public static String PERMISSION_PORTAL_ADMIN_CATALOG = "admin.portal.partner.provider.catalog";
    
    private String parsedActions = null;
    
    /** Create an ingrid permission !
     * @param name resource the permission applies to e.g. "admin.portal"
     * @param actions "*" will be replaced with "view,edit" to match Jetspeed actions and avoid exception ! 
     */
    public IngridPermission(String name, String actions) {
    	this(INGRID_PERMISSION, name, actions);
    }

    /** Create an ingrid permission !
     * @param type type of permission used for jetspeed !
     * @param name resource the permission applies to e.g. "admin.portal"
     * @param actions "*" will be replaced with "view,edit" to match Jetspeed actions and avoid exception ! 
     */
    public IngridPermission(String type, String name, String actions) {
    	// we have to replace "*" cause "*" action unknown to jetspeed, see JetspeedActions
        super(type, name, ("*".equals(actions)?"view,edit":actions));
        this.myBasicPermission = new BasicPermission(name) {};
        this.parsedActions = parseActions(actions);
    }

    /**
     * @see java.security.Permission#hashCode()
     */
    public int hashCode() {
        return getName().concat(getActions()).hashCode();
    }

    public BasicPermission getBasicPermission() {
		return myBasicPermission;
	}

    /**
     * Checks if the permission is implied in this.
     *  
     * Checks the name of the permission according to the
     * hierarchical property naming convention AND checks if the
     * actions are implied.
     * 
     * @see java.security.BasicPermission#implies(java.security.Permission)
     *
     * @param permission The permission to check.
     * @param checkActions true to check the actions as well, false to check not
     * @return true if this implies permission, fals if not. 
     *
     */
    public boolean implies(Permission permission, boolean checkActions) {

        // The permission to check must be an instance of our class
        if (!(permission instanceof IngridPermission)) {
            return false;
        }

        // first check basic permission part
        if (!myBasicPermission.implies(((IngridPermission)permission).getBasicPermission())) {
            return false;
        }
        
        // exit if action check is disabled
        if (!checkActions) {
            return true;
        }
        
        // check actions for equality and empty permission actions
        if (((IngridPermission)permission).getParsedActions().equals(this.parsedActions)) {
            return true;
        } else if (permission.getActions().length() == 0) {
            return false;
        }
        
        // check for '*' permission
        if (parsedActions.equals("|*|")) {
            return true;
        }
        
        // check for implied actions
        StringTokenizer tokenizer = new StringTokenizer(permission.getActions(), ",\t ");
        while (tokenizer.hasMoreTokens()) {
            String action = "|".concat(tokenizer.nextToken()).concat("|");
            if (parsedActions.indexOf(action) == -1) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * @see java.security.Permission#implies(java.security.Permission)
     */
    public boolean implies(Permission permission) {
        return implies(permission, true);
    }
    
    
    /**
     * Compares obj with the permission object. Compares the class type, 
     * the permissions name and the permsissions actions.
     * 
     * 
     * @see java.security.BasicPermission#equals(java.lang.Object)
     */
    public boolean equals(Object obj) {
        // The object to check must be an instance of our class
        if (!(obj instanceof IngridPermission)) {
            return false;
        }

        // first check basic permission part
        if (!myBasicPermission.equals(((IngridPermission)obj).getBasicPermission())) {
            return false; 
        }
        IngridPermission p = (IngridPermission)obj;
        
        if (p.getParsedActions().equals(parsedActions)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Our IngridPermissionCollection simulates a BasicPermissionCollection !
     * 
     * @see org.apache.jetspeed.security.spi.impl.BaseJetspeedPermission#newPermissionCollection()
     */
    public PermissionCollection newPermissionCollection() {
        return new IngridPermissionCollection();
    }

    /**
     * Return the parsed actions (used for performant equal check). 
     * The parsed actions String has the format |action1|action2|....|
     *  
     * @return The parsed actions string of the permission.
     */
    protected String getParsedActions() {
        return parsedActions;
    }
    
    
    /**
     * Parses the actions into a internal representation for
     * more performant implication checking. 
     * 
     * @param actions The actions to parse.
     */
    private String parseActions(String actions) {
        if (actions == null || actions.length() == 0) {
            return "";
        }
        String result = "|";
        StringTokenizer tokenizer = new StringTokenizer(actions, ",\t ");
        while (tokenizer.hasMoreTokens()) {
            result = result.concat(tokenizer.nextToken()).concat("|");
        }
        return result;
    }


}
