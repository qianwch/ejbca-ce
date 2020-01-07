package org.ejbca.ui.web.admin.filter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

public class ServletAuthenticationFilter implements Filter {

    private static final Logger log = Logger.getLogger(ServletAuthenticationFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        final HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        boolean hasAuthenticationError = false;
        String authenticationErrorMessage = "";
        String authenticationErrorPublicMessage = "Authorization Denied";
        try {
            final EjbcaWebBean ejbcaWebBean = getEjbcaWebBean(httpServletRequest);
            ejbcaWebBean.initialize(httpServletRequest, getAccessResourcesByRequestURI(httpServletRequest.getRequestURI()));
            final X509Certificate x509Certificate = ejbcaWebBean.getClientX509Certificate(httpServletRequest);
            if (x509Certificate != null) {
                final AuthenticationToken admin = ejbcaWebBean.getAdminObject();
                if(admin != null) {
                    httpServletRequest.setAttribute("authenticationtoken", admin);
                    filterChain.doFilter(servletRequest, servletResponse);
                }
                else {
                    hasAuthenticationError = true;
                    authenticationErrorMessage = "Authorization denied for certificate: " + CertTools.getSubjectDN(x509Certificate);
                    authenticationErrorPublicMessage = authenticationErrorMessage;
                }
            }
            else {
                hasAuthenticationError = true;
                authenticationErrorMessage = "No client certificate sent.";
                authenticationErrorPublicMessage = "This operation requires certificate authentication!";
            }
        }
        catch (Exception ex) {
            log.info("Could not initialize for client " + httpServletRequest.getRemoteAddr());
            log.debug("Client initialization failed", ex);
            throw new ServletException("Cannot process the request.");
        }
        if(hasAuthenticationError) {
            log.info("Client " + httpServletRequest.getRemoteAddr() + " was denied. " + authenticationErrorMessage);
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, authenticationErrorPublicMessage);
        }
    }

    @Override
    public void destroy() {
    }

    private EjbcaWebBean getEjbcaWebBean(HttpServletRequest req) throws ServletException {
        final HttpSession session = req.getSession();
        EjbcaWebBean ejbcawebbean = (EjbcaWebBean) session.getAttribute("ejbcawebbean");
        if (ejbcawebbean == null) {
            try {
                ejbcawebbean = (EjbcaWebBean) java.beans.Beans.instantiate(
                        Thread.currentThread().getContextClassLoader(),
                        EjbcaWebBeanImpl.class.getName()
                );
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            } catch (Exception exc) {
                throw new ServletException("Cannot create bean of class " + EjbcaWebBeanImpl.class.getName(), exc);
            }
            session.setAttribute("ejbcawebbean", ejbcawebbean);
        }
        return ejbcawebbean;
    }

    private String getAccessResourcesByRequestURI(final String requestURI) throws ServletException {
        if (StringUtils.isNotBlank(requestURI)) {
            if (requestURI.startsWith("/ca/certreq")) {
                return AccessRulesConstants.REGULAR_CREATEENDENTITY;
            }
            else if(requestURI.startsWith("/ca/editcas/cacertreq")) {
                return StandardRules.ROLE_ROOT.resource();
            }
            else if(requestURI.startsWith("/ca/cacert")) {
                return AccessRulesConstants.REGULAR_VIEWCERTIFICATE;
            }
            else if(requestURI.startsWith("/ca/exportca")) {
                return StandardRules.ROLE_ROOT.resource();
            }
            else if(requestURI.startsWith("/ca/endentitycert")) {
                return AccessRulesConstants.REGULAR_VIEWCERTIFICATE;
            }
            else if(requestURI.startsWith("/ca/getcrl/getcrl")) {
                return AccessRulesConstants.REGULAR_VIEWCERTIFICATE;
            }
            else if(requestURI.startsWith("/profilesexport")) {
                return AccessRulesConstants.ROLE_ADMINISTRATOR;
            }
            else if(requestURI.startsWith("/cryptotoken/cryptoTokenDownloads")) {
                return CryptoTokenRules.VIEW.resource();
            }
        }
        throw new ServletException("Cannot define AccessResources.");
    }
}
