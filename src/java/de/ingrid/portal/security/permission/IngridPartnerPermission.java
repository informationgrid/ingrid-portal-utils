/*
 * Copyright (c) 2006 wemove digital solutions. All rights reserved.
 */
package de.ingrid.portal.security.permission;

import java.security.Permission;
import java.util.ArrayList;
import java.util.StringTokenizer;

/**
 * This class represent the portal permissions that are further restricted
 * partners.
 * 
 * The permissions are i.e.
 * 
 *   portal.admin.index - for changing the search engine index (urls, start, stop)
 *   portal.admin.content.rss - for changing the rss feeds in the portal
 *
 * @author joachim@wemove.com
 */
public class IngridPartnerPermission extends IngridPermission {

    private static final long serialVersionUID = 7405952399854216042L;

    /**
     * Constructor
     * 
     * @param name The permissions name.
     * @param partners The partners the permission applies for (comma separated list, 'all' for all)
     */
    public IngridPartnerPermission(String name, String partners) {
        super(name, partners);
    }
 
    /**
     * Returns all Partners
     * 
     * @return List of partners.
     */
    public ArrayList getPartners() {
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
        
        // permission counts for all partner
        if (this.getParsedActions().indexOf("|all|") != -1) {
            // do not check actions anymore
            return super.implies(permission, false);
        } else {
            return super.implies(permission, true);
        }
    }
    
    
}
