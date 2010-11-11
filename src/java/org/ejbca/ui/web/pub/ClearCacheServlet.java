/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.web.pub;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Set;

import javax.ejb.CreateException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * Servlet used to clear all caches (Global Configuration Cache, End Entity Profile Cache, 
 * Certificate Profile Cache, Log Configuration Cache, Authorization Cache and CA Cache).
 *
 * @author Aveen Ismail
 * @version $Id$
 */
public class ClearCacheServlet extends HttpServlet {

	private static final long serialVersionUID = -8563174167843989458L;
	private static final Logger log = Logger.getLogger(ClearCacheServlet.class);
	
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }
  
    public void doPost(HttpServletRequest req, HttpServletResponse res)	throws IOException, ServletException {
    	doGet(req,res);
    }


	public void doGet(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
		if (log.isTraceEnabled()) {
			log.trace(">doGet()");
		}
        
        if (StringUtils.equals(req.getParameter("command"), "clearcaches")) {
            if(!acceptedHost(req.getRemoteHost())) {
        		if (log.isDebugEnabled()) {
        			log.debug("Clear cache request denied from host "+req.getRemoteHost());
        		}
        		res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The remote host "+req.getRemoteHost()+" is unknown");
        	} else {        	
        		try {
        			IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
        			IRaAdminSessionLocal raadminsession = raadminsessionhome.create();
        			raadminsession.flushGlobalConfigurationCache();
        			if(log.isDebugEnabled()){
        				log.debug("Global Configuration cache cleared");
        			}
        			raadminsession.flushProfileCache();
        			if(log.isDebugEnabled()) {
        				log.debug("RA Profile cache cleared");
        			}

        			ICertificateStoreSessionLocalHome certstoresessionhome = (ICertificateStoreSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
        			ICertificateStoreSessionLocal certstoresession = certstoresessionhome.create();
        			certstoresession.flushProfileCache();
        			if(log.isDebugEnabled()) {
        				log.debug("Cert Profile cache cleared");
        			}

        			IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
        			IAuthorizationSessionLocal authorizationsession = authorizationsessionhome.create();
        			authorizationsession.flushAuthorizationRuleCache();
        			if(log.isDebugEnabled()) {
        				log.debug("Authorization Rule cache cleared");
        			}

        			ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ILogSessionLocalHome.COMP_NAME);
        			ILogSessionLocal logsession = logsessionhome.create();
        			logsession.flushConfigurationCache();
        			if(log.isDebugEnabled()) {
        				log.debug("Log Configuration cache cleared");
        			}

        			ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
        			ICAAdminSessionLocal caadminsession = caadminsessionhome.create();
        			caadminsession.flushCACache();
        			if(log.isDebugEnabled()) {
        				log.debug("CA cache cleared");
        			}
        		} catch (CreateException e) {
        			log.info("Error flushing cache:", e);
        			res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Failed to create Session instance, see server.log");
        		}
        	}
        } else {
    		if (log.isDebugEnabled()) {
    			log.debug("No clearcaches command (?command=clearcaches) received, returning bad request.");
    		}
			res.sendError(HttpServletResponse.SC_BAD_REQUEST, "No command.");
        }
		if (log.isTraceEnabled()) {
			log.trace("<doGet()");
		}
    }

    private boolean acceptedHost(String remotehost) {
    	if (log.isTraceEnabled()) {
    		log.trace(">acceptedHost: "+remotehost);
    	}
    	boolean ret = false;
    	try {
    		IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
    		IRaAdminSessionLocal raadminsession = raadminsessionhome.create();
    		GlobalConfiguration gc = raadminsession.loadGlobalConfiguration(new Admin(Admin.TYPE_INTERNALUSER));
    		Set nodes = gc.getNodesInCluster();
    		Iterator itr = nodes.iterator();
    		String nodename = null;
    		while(itr.hasNext()){
    			nodename = (String) itr.next();
    			try {
    				if(StringUtils.equals(remotehost, InetAddress.getByName(nodename).getHostAddress())) {
    					ret = true;
    				}
    			} catch (UnknownHostException e) {
    				if (log.isDebugEnabled()) {
    					log.debug("Unknown host '"+nodename+"': "+e.getMessage());
    				}
    			}
    		}
    	} catch (CreateException e) {
    		log.error("Failed to create RAAdminSession instance: ", e);
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<acceptedHost: "+ret);
    	}
    	return ret;
    }
}
