/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.permission;

import java.security.BasicPermission;
import java.security.Permission;
import java.util.StringTokenizer;

/**
 * General Ingrid permission class. Represents a permission with the parameter 
 * name and actions. Provides basic permission methods.
 *
 * @author joachim@wemove.com
 */
/**
 * TODO Describe your created type (class, etc.) here.
 *
 * @author joachim@wemove.com
 */
public class IngridPermission extends BasicPermission {

    private static final long serialVersionUID = 2246210603932755952L;
    
    // permission to change all portal specific stuff
    public static String PERMISSION_PORTAL_ADMIN = "portal.admin";
    // permission to change all portal content stuff
    public static String PERMISSION_PORTAL_ADMIN_CONTENT = "portal.admin.content";
    // permission to change the search engine index (urls, start, stop)
    public static String PERMISSION_PORTAL_ADMIN_INDEX = "portal.admin.index";
    // permission to change the search engine index (catalog topics, measure, service)
    public static String PERMISSION_PORTAL_ADMIN_CATALOG = "portal.admin.catalog";
    // permission to change the iplugs parameters
    public static String PERMISSION_PORTAL_ADMIN_IPLUG = "portal.admin.iplug";
    // permission to admin the users of a certain partner
    public static String PERMISSION_PORTAL_ADMIN_PARTNER = "portal.admin.partner";
    // permission to see the portal statistics
    public static String PERMISSION_PORTAL_ADMIN_STATISTICS = "portal.admin.statistics";
    // permission to admin the WMS server
    public static String PERMISSION_PORTAL_ADMIN_WMS = "portal.admin.wms";
    
    private String actions = null;
    private String parsedActions = null;
    
    public IngridPermission(String name, String actions) {
        super(name);
        this.actions = actions;
        this.parsedActions = parseActions(actions);
    }

    /**
     * @see java.security.Permission#hashCode()
     */
    public int hashCode() {
        return getName().concat(actions).hashCode();
    }

    /**
     * @see java.security.Permission#getActions()
     */
    public String getActions() {
        return actions;
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

        // check permissions name and class
        if (!super.implies(permission)) {
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
        if (!super.equals(obj)) {
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
