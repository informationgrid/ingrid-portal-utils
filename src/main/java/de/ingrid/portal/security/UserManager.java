/* Copyright 2004 Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.ingrid.portal.security;

import java.sql.Date;
import java.util.Collection;
import java.util.Iterator;

import org.apache.jetspeed.security.User;

/**
 * <p>
 * Describes the interface for managing users and provides access to the
 * {@link User}.
 * </p>
 * 
 * @author <a href="mailto:dlestrat@apache.org">David Le Strat </a>
 */
public interface UserManager
{
    /**
     * @return the name of the anonymous user
     */
    String getAnonymousUser();
    
    /**
     * <p>
     * Authenticate a user.
     * </p>
     * 
     * @param username The user name.
     * @param password The user password.
     * @return Whether or not a user is authenticated.
     */
    boolean authenticate(String username, String password);

    /**
     * <p>
     * Add a new user provided a username and password.
     * </p>
     * 
     * @param username The user name.
     * @param password The password.
     * @throws Throws a security exception.
     */
    void addUser(String username, String password) throws SecurityException;

    /**
     * <p>
     * Add a new user provided a username and password in the specified authentication
     * provider store.
     * </p>
     * 
     * @param username The user name.
     * @param password The password.
     * @param atnProviderName The authentication provider name.
     * @throws Throws a security exception.
     */
    void addUser(String username, String password, String atnProviderName) throws SecurityException;

    
    /**
     * <p>
     * Import a new user with username and password and allow to bypass the enconding algorithm
     * </p>
     * 
     * @param username The user name.
     * @param password The password.
     * @param passThrough If true the provided password will not be validated/encoded
     * @throws Throws a security exception.
     */
    void importUser(String username, String password, boolean passThrough) throws SecurityException;

    /**
     * <p>
     * Import a new user with username and password in the specified authentication
     * provider store and allow to bypass the enconding algorithm
     * </p>
     * 
     * @param username The user name.
     * @param password The password.
     * @param atnProviderName The authentication provider name.
     * @param passThrough If true the provided password will not be validated/encoded
     * @throws Throws a security exception.
     */
    void importUser(String username, String password, String atnProviderName, boolean passThrough) throws SecurityException;

    
    /**
     * <p>
     * Remove a user. If there is a {@link java.util.prefs.Preferences}node for
     * profile properties associated to this user, it will be removed as well.
     * </p>
     * <p>
     * {@link java.security.Permission}for this user will be removed as well.
     * </p>
     * 
     * @param username The user name.
     * @throws Throws a security exception.
     */
    void removeUser(String username) throws SecurityException;

    /**
     * <p>
     * Whether or not a user exists.
     * </p>
     * 
     * @param username The user name.
     * @return Whether or not a user exists.
     */
    boolean userExists(String username);

    /**
     * <p>
     * Get a {@link User}for a given username.
     * </p>
     * 
     * @param username The username.
     * @return The {@link User}.
     * @throws Throws a security exception if the user cannot be found.
     */
    User getUser(String username) throws SecurityException;

    /**
     * <p>
     * An iterator of {@link User}finding users matching the corresponding
     * filter criteria.
     * </p>
     * TODO Complete filter implementation.
     * 
     * @param filter The filter used to retrieve matching users.
     * @return The Iterator of {@link User}.
     */
    Iterator getUsers(String filter) throws SecurityException;

    /**
     * <p>
     * An iterator of user names, finding users matching the corresponding
     * filter criteria.
     * </p>
     * TODO Complete filter implementation.
     * 
     * @param filter The filter used to retrieve matching users.
     * @return The Iterator of {@link User}.
     */
    Iterator getUserNames(String filter) throws SecurityException;

    /**
     * <p>
     * A collection of {@link User}for all the users in a specific role.
     * </p>
     * 
     * @param roleFullPathName The role name full path (e.g.
     *            theRoleName.theRoleNameChild).
     * @return A Collection of {@link User}.
     * @throws Throws a security exception if the role does not exist.
     */
    Collection getUsersInRole(String roleFullPathName) throws SecurityException;
    
    /**
     * <p>A collection of {@link User} for a specific group.</p>
     * @param groupFullPathName The group name full path
     *                          (e.g. theGroupName.theGroupChildName).
     * @return A collection of {@link User}.
     * @throws Throws security exception if the group does not exist.
     */
    Collection getUsersInGroup(String groupFullPathName) throws SecurityException;
    
    /**
     * <p>
     * Set the user password.
     * </p>
     * 
     * @param username The user name.
     * @param oldPassword The old password.
     * @param newPassword The new password.
     * @throws Throws a security exception.
     */
    void setPassword(String username, String oldPassword, String newPassword) throws SecurityException;

    /**
     * <p>
     * Set the update required state of the user password credential.
     * </p>
     * 
     * @param userName The user name.
     * @param updateRequired The update required state.
     * @throws Throws a security exception.
     */
    void setPasswordUpdateRequired(String userName, boolean updateRequired) throws SecurityException;

    /**
     * <p>
     * Set the enabled state of the user password credential.
     * </p>
     * 
     * @param userName The user name.
     * @param enabled The enabled state.
     * @throws Throws a security exception.
     */
    void setPasswordEnabled(String userName, boolean enabled) throws SecurityException;

    /**
     * Enable or disable a user.
     * @param userName The user name
     * @param enabled enabled flag for the user
     */
    void setUserEnabled(String userName, boolean enabled) throws SecurityException;

    /**
     * <p>
     * Set the expiration date and the expired flag of the password credential.</p>
     * <p>
     * If a date equal or before the current date is provided, the expired flag will be set to true,
     * otherwise to false.</p>
     * 
     * @param userName The user name.
     * @param expirationDate The expiration date to set.
     * @throws Throws a security exception.
     */
    void setPasswordExpiration(String userName, Date expirationDate) throws SecurityException;
}