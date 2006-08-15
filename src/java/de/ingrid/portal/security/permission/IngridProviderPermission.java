/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.permission;

import java.security.Permission;
import java.util.ArrayList;
import java.util.StringTokenizer;

/**
 * This class represent the portal permissions that are further restricted
 * providers.
 * 
 * The permissions are i.e.
 * 
 *   portal.admin.index - for changing the search engine index (urls, start, stop)
 *   portal.admin.content.rss - for changing the rss feeds in the portal
 *
 * @author joachim@wemove.com
 */
public class IngridProviderPermission extends IngridPermission {

    private static final long serialVersionUID = 7405952399854216041L;

    /**
     * Constructor
     * 
     * @param name The permissions name.
     * @param providers The providers the permission applies for (comma separated list, 'all' for all)
     */
    public IngridProviderPermission(String name, String providers) {
        super(name, providers);
    }
    
    /**
     * Returns all Providers
     * 
     * @return List of providers.
     */
    public ArrayList getProviders() {
        ArrayList result = new ArrayList();
        StringTokenizer tokenizer = new StringTokenizer(this.getActions(), ",\t ");
        while (tokenizer.hasMoreTokens()) {
            result.add(tokenizer.nextToken());
        }
        return result;
    }
    
    /**
     * @see de.ingrid.portal.security.permission.IngridPermission#implies(java.security.Permission)
     */
    public boolean implies(Permission permission) {
        
        // permission counts for all provider
        if (this.getParsedActions().indexOf("|all|") != -1) {
            // do not check actions anymore
            return super.implies(permission, false);
        } else {
            return super.implies(permission, true);
        }
    }
    
}
