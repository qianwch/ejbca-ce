/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.cainterface;

import java.beans.Beans;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * Base servlet class for all AdminWeb pages that require authentication.
 * 
 * @version $Id$
 */
public abstract class BaseAdminServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(BaseAdminServlet.class);

    @EJB
    private WebAuthenticationProviderSessionLocal authenticationSession;
    
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            CryptoProviderTools.installBCProvider(); // Install BouncyCastle provider
        } catch (Exception e) {
            throw new ServletException(e);
        }
        if (authenticationSession == null) {
            log.error("Local EJB injection failed of AuthenticationSession");
        }
    }
    
    /**
     * Gets the RAInterfaceBean object, or creates and initializes a new RAInterfaceBean if not already created.
     */
    final RAInterfaceBean getRaBean(HttpServletRequest req) throws ServletException {
        HttpSession session = req.getSession();
        RAInterfaceBean rabean = (RAInterfaceBean) session.getAttribute("rabean");
        if (rabean == null) {
            try {
                rabean = (RAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        org.ejbca.ui.web.admin.rainterface.RAInterfaceBean.class.getName());
            } catch (ClassNotFoundException e) {
                throw new ServletException(e);
            } catch (Exception e) {
                throw new ServletException("Unable to instantiate RAInterfaceBean", e);
            }
            try {
                rabean.initialize(req, getEjbcaWebBean(req));
            } catch (Exception e) {
                throw new ServletException("Cannot initialize RAInterfaceBean", e);
            }
            session.setAttribute("rabean", rabean);
        }
        return rabean;
    }

    /**
     * Gets the EjbcaWebBean object, or creates and initializes a new EjbcaWebBeanImpl if not already created.
     */
    protected final EjbcaWebBean getEjbcaWebBean(HttpServletRequest req) throws ServletException {
        HttpSession session = req.getSession();
        EjbcaWebBean ejbcawebbean = (EjbcaWebBean) session.getAttribute("ejbcawebbean");
        if (ejbcawebbean == null) {
            try {
                ejbcawebbean = (EjbcaWebBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        EjbcaWebBeanImpl.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            } catch (Exception exc) {
                throw new ServletException(" Cannot create bean of class " + EjbcaWebBeanImpl.class.getName(), exc);
            }
            session.setAttribute("ejbcawebbean", ejbcawebbean);
        }
        return ejbcawebbean;
    }

    protected AuthenticationToken getAuthenticationToken(final HttpServletRequest httpServletRequest) throws ServletException {
        final Object authenticationTokenAttribute = httpServletRequest.getAttribute("authenticationtoken");
        if(authenticationTokenAttribute == null) {
            throw new ServletException("Cannot get AuthenticationToken");
        }
        return (AuthenticationToken) authenticationTokenAttribute;
    }

}
