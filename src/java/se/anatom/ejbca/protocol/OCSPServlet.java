package se.anatom.ejbca.protocol;

import java.io.*;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;
import javax.servlet.*;
import javax.servlet.http.*;

import com.ophios.ocsp.*;
import com.ophios.ocsp.extensions.*;
import com.ophios.x509.X509Extension;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.util.CertTools;

import org.apache.log4j.Logger;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 * 
 * @author Thomas Meckel (Ophios GmbH)
 * @version  $Id: OCSPServlet.java,v 1.1.2.3 2003-09-25 13:32:57 anatom Exp $
 */
public class OCSPServlet extends HttpServlet {

    private static Logger m_log = Logger.getLogger(OCSPServlet.class);

    private ICertificateStoreSessionRemote m_cssr;
    private Admin m_adm;

    private PrivateKey m_signkey;
    private X509Certificate [] m_signcerts;
    private int m_responderIdx;
    private boolean m_reqMustBeSigned;

    protected Collection loadCertificates() 
        throws IOException {
        try {
            Collection cl;
            Iterator iter;
            
            return m_cssr.findCertificatesByType(m_adm, SecConst.CERTTYPE_CA + SecConst.CERTTYPE_ROOTCA, null);
        } catch (Exception e) {
            m_log.error("Unable to load CA certificates from CA store.", e);
            throw new IOException(e.toString());
        }
    }

    protected X509Certificate findCAByHash(OCSPCertificateID certId, Collection certs)
        throws NoSuchAlgorithmException {
        if (null == certId) {
            throw new IllegalArgumentException();
        }
        if (null == certs || certs.isEmpty()) {
            m_log.info("The passed certificate collection is empty.");
            return null;
        }
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            X509Certificate cacert = (X509Certificate)iter.next();
            OCSPCertificateHash chash = new OCSPCertificateHash(cacert
                                                                , certId.getHashAlgorithmOID());
            if (m_log.isDebugEnabled()) {
                m_log.debug("Comparing the following certificate hashes:\n"
                            + " Hash algorithm : '" + certId.getHashAlgorithmOID() + "'\n"
                            + " CA certificate hashes\n"
                            + "      Name hash : '" + Hex.encode(chash.getIssuerNameHash()) + "'\n"
                            + "      Key hash  : '" + Hex.encode(chash.getIssuerKeyHash()) + "'\n"
                            + " OCSP certificate hashes\n"
                            + "      Name hash : '" + Hex.encode(certId.getIssuerNameHash()) + "'\n"
                            + "      Key hash  : '" + Hex.encode(certId.getIssuerKeyHash()) + "'\n");
            }
            if (chash.equals(certId)) {
                return cacert;
            }
        }
        return null;
    }

    protected int findCertificateIndexBySubject(X509Certificate [] certs, String subject) 
    {
        if (certs == null || null == subject) {
            throw new IllegalArgumentException();
        }

        if (certs.length <= 0 || subject.length() <= 0) {
            return -1;
        }

        for (int i=0; i<certs.length; i++) {
            if (m_log.isDebugEnabled()) {
                m_log.debug("Checking certificate '"
                            + certs[i].getSubjectDN().getName()
                            + "' against '"
                            + subject
                            + "'");
            }
            if (subject.equalsIgnoreCase(CertTools.stringToBCDNString(certs[i].getSubjectDN().getName()))) {
                return i;
            }
        }
        return -1;
    }
    
    public void init(ServletConfig config) 
        throws ServletException {
        super.init(config);
        
        try {
            String initparam;
            String kspath;
            String kspwd;
            String kstype;
            String pkalias;
            
            InitialContext ctx = new InitialContext();
            ICertificateStoreSessionHome castorehome = 
              (ICertificateStoreSessionHome)PortableRemoteObject.narrow(ctx.lookup("CertificateStoreSession")
                                                                        , ICertificateStoreSessionHome.class );
            m_cssr = castorehome.create();
            m_adm = new Admin(Admin.TYPE_INTERNALUSER);

            {
                File cwd = new File(".");
                m_log.info("OCSPServlet current working directory : '"
                            + cwd.getAbsolutePath()
                            + "'");
            }
            
            kspath = config.getInitParameter("keyStore");
            if (null == kspath || kspath.length() <= 0) {
                m_log.error("Path to keystore not defined in initialization parameters.");
                throw new ServletException("Missing keystore path.");
            }
            kspwd = config.getInitParameter("keyStorePass");
            if (null == kspwd || kspwd.length() <= 0) {
                m_log.error("Keystore password not defined in initialization parameters.");
                throw new ServletException("Missing keystore password.");
            }
            kstype = config.getInitParameter("keyStoreType");
            if (null == kstype || kstype.length() <= 0) {
                m_log.warn("Keystore format not defined. Assuming PKCS12 as default.");
                kstype = "PKCS12";
            }

            if (m_log.isDebugEnabled()) {
                m_log.debug("Keystore type     : '" + kstype + "'\n"
                            + "Keystore path     : '" + kspath + "'\n"
                            + "Keystore passwd   : '" + kspwd + "'\n");
            }
            KeyStore ks = KeyStore.getInstance(kstype);
            ks.load(new FileInputStream(kspath), kspwd.toCharArray());

            if (m_log.isDebugEnabled()) {
                StringBuffer sb = new StringBuffer();
                Enumeration aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    sb.append(", ");
                    sb.append(aliases.nextElement());
                }
                sb.delete(0, ", ".length());
                m_log.debug("Available aliases is keystore : '"
                            + sb.toString()
                            + "'");                            
            }
            /*
             * load OCSP signing (private) key
             */
            pkalias = config.getInitParameter("privateKeyAlias");
            if (null == pkalias || pkalias.length() <= 0) {
                pkalias = "ocspsignkey";
            }            
            initparam = config.getInitParameter("privateKeyPass");
            if (null != initparam && initparam.length() <= 0) {
                initparam = null;
            }
            if (!ks.isKeyEntry(pkalias)) {
                m_log.error("The private key alias '" 
                            + pkalias 
                            + "' does not denote a private key in the specified keystore.");
                throw new ServletException("Unable to find OCSP signing key.");
            }
            if (m_log.isDebugEnabled()) {
                m_log.debug("Private key alias     : '" + pkalias + "'\n"
                            + "Private key pass      : '" + (initparam == null ? "null" : initparam) + "'");
            }
            m_signkey = (PrivateKey)ks.getKey(pkalias
                                              , (initparam == null ? null : initparam.toCharArray()));
            if (null == m_signkey) {
                final String msg = "Unable to load private key from keystore.";
                m_log.error(msg);
                throw new ServletException(msg);                
            }
            /*
             * load OCSP signing certificate
             */
            initparam = config.getInitParameter("certificateAlias");
            if (null == initparam || initparam.length() <= 0) {
                initparam = "ocspsigncert";
            }
            if (m_log.isDebugEnabled()) {
                m_log.debug("Certificate alias : '" + initparam + "'\n");
            }

            Certificate [] certs = ks.getCertificateChain(initparam);
            if (null == certs) {
                final String msg = "Unable to load certificate (chain) from keystore.";
                m_log.error(msg);
                throw new ServletException(msg);
            }
            m_signcerts = new X509Certificate[certs.length];
            for (int i=0; i<certs.length; i++) {
                if (!(certs[i] instanceof X509Certificate)) {
                    final String msg = "Certificate (chain) from keytsore must be of type 'X509Certificate'.";
                    m_log.error(msg);
                    throw new ServletException(msg);
                }
                m_signcerts[i] = (X509Certificate)certs[i];
            }

            initparam = config.getInitParameter("responderID");
            if (null == initparam || initparam.length() <= 0) {
                final String msg = "Required parameter 'responderID' not set.";
                m_log.error(msg);
                throw new ServletException(msg);
            }
            // Normalize DN in initparam
            initparam = CertTools.stringToBCDNString(initparam);
            m_responderIdx = findCertificateIndexBySubject(m_signcerts, initparam);
            if (m_responderIdx < 0) {
                final String msg = "Unable to find certificate for given responderID.";
                m_log.error(msg);
                throw new ServletException(msg);
            }
            initparam = config.getInitParameter("enforceRequestSigning");
            if (null == initparam || initparam.length() <= 0) {
                m_reqMustBeSigned = true;
            } else {
                m_reqMustBeSigned = Boolean.getBoolean(initparam);
            }
        } catch(Exception e) {
            m_log.error("Unable to initialize OCSPServlet.", e);
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws IOException, ServletException {
        m_log.debug(">doPost()");

        OCSPBasicResponse res;
        try {
            Collection cacerts = loadCertificates();            
            X509Extension ext;
            OCSPRequest req = OCSPRequest.load(request.getInputStream()); 

            if (m_log.isDebugEnabled()) {
                StringBuffer certInfo = new StringBuffer();
                Iterator iter = cacerts.iterator();
                while (iter.hasNext()) {
                    X509Certificate cert = (X509Certificate)iter.next();
                    certInfo.append(cert.getSubjectDN().getName());
                    certInfo.append(',');
                    certInfo.append(cert.getSerialNumber().toString());
                    certInfo.append('\n');
                }
                m_log.debug("Found the following CA certificates : \n" 
                            + certInfo.toString());
            }
            res = new OCSPBasicResponse();
            ext = req.getExtension(OCSPNonceExtension.ID_PKIX_OCSP_NONCE);
            if (null != ext) {
                res.addExtension(ext);
            }
            res.setResponderID(new OCSPResponderIDKeyHash(m_signcerts[m_responderIdx]));
            
            /**
             * check the signature if contained in request.
             * if the request does not contain a signature
             * and the servlet is configured in the way 
             * the a signature is required we send back
             * 'sigRequired' response.
             */
            try {
                req.verify();
            } catch (SignatureException e) {
                m_log.info("Signature of incoming OCSPRequest is invalid.");
                //res.setStatus(OCSPResponse.SIG_REQUIRED);
                throw new ServletException(e.toString());
            }
            
            /**
             * check if requestor is allowed to talk
             * to the CA if not send back a 'unauthorized'
             * response
             */
            //res.setStatus(OCSPResponse.UNAUTHORIZED);

            /*
            MultiHashMap mhm = new MultiHashMap(); 
            Enumeration sreqs = req.singleRequests();
            while (sreqs.hasMoreElements()) {
                X509Certificate cacert = null;
                X509Certificate cert = null;
                OCSPSingleRequest sreq = (OCSPSingleRequest)sreqs.nextElement();
                OCSPCertificateID certId = sreq.getCertificateID();
                
                try {
                    cacert = findCAByHash(certId, cacerts);
                } catch (NoSuchAlgorithmException e) {
                    m_log.info("Unable to generate CA certificate hash.", e);    
                    cacert = null;
                    continue;
                }
                if (null == cacert) {
                    m_log.info("Unable to find CA certificate by hash.");

                    OCSPSingleResponse sres = new OCSPSingleResponse(certId);
                    sres.setCertStatus(OCSPSingleResponse.CERTSTATUS_UNKNOWN);
                    res.addSingleResponse(sres);
                    continue;                    
                }
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Associating CA certificate with certificate id from OCSP request.");
                }
                mhm.put(cacert, certId);
            }

            Iterator caiter = mhm.keySet().iterator();
            while (caiter.hasNext()) {
                Collection certs;
                Collection certIds;
                ArrayList sernos;
                Iterator iter;
                X509Certificate cacert;
                OCSPCertificateID certId;
                Hashtable serToCertId = new Hashtable();

                cacert = (X509Certificate)caiter.next();
                certIds = (Collection)mhm.get(cacert);
                sernos = new ArrayList();
                iter = certIds.iterator();
                while (iter.hasNext()) {
                    certId = (OCSPCertificateID)iter.next();
                    serToCertId.put(certId.getCertificateSerial(), certId);
                    sernos.add(certId.getCertificateSerial());
                }

                certs = m_cssr.isRevoked(m_adm
                                         , cacert.getSubjectDN().getName()
                                         , sernos);
                iter = certs.iterator();
                while (iter.hasNext()) {
                    RevokedCertInfo rci = (RevokedCertInfo)iter.next();
                    certId = (OCSPCertificateID)serToCertId.get(rci.getUserCertificate());
                    if (null == certId) {
                        throw new OCSPInternalErrorException("CA returned unknown certificate.");
                    }
                    OCSPSingleResponse sr = new OCSPSingleResponse(certId);
                    if (rci.getReason() > 0) {
                        OCSPRevokedInfo ori = new OCSPRevokedInfo();
                        ori.setRevocationTime(rci.getRevocationDate());
                        ori.setRevocationReason(rci.getReason());
                        sr.setCertStatus(OCSPSingleResponse.CERTSTATUS_REVOKED);                        
                        sr.setRevocationInfo(ori);
                    } else {
                        sr.setCertStatus(OCSPSingleResponse.CERTSTATUS_GOOD);
                    }
                    res.addSingleResponse(sr);
                }
            }
            */
            if (req.singleRequestCount() <= 0) {
                m_log.error("The OCSP request does not contain any simpleRequest entities.");
                res.setStatus(OCSPResponse.MALFORMED_REQUEST);                
            } else {
                Enumeration sreqs = req.singleRequests();
                while (sreqs.hasMoreElements()) {
                    OCSPSingleRequest sreq = (OCSPSingleRequest)sreqs.nextElement();
                    X509Certificate cacert = null;
                    X509Certificate cert = null;
                    OCSPCertificateID certId = sreq.getCertificateID();
                    RevokedCertInfo rci;
                
                    try {
                        cacert = findCAByHash(certId, cacerts);
                    } catch (NoSuchAlgorithmException e) {
                        m_log.info("Unable to generate CA certificate hash.", e);    
                        cacert = null;
                        continue;
                    }
                    if (null == cacert) {
                        m_log.info("Unable to find CA certificate by hash.");

                        OCSPSingleResponse sres = new OCSPSingleResponse(certId);
                        sres.setCertStatus(OCSPSingleResponse.CERTSTATUS_UNKNOWN);
                        res.addSingleResponse(sres);
                        continue;                    
                    }

                    rci = m_cssr.isRevoked(m_adm
                                           , cacert.getSubjectDN().getName()
                                           , certId.getCertificateSerial());
                    if (null == rci) {
                        m_log.info("Unable to find revocation information for certificate with serial '"
                                   + certId.getCertificateSerial() + "'"
                                   + " from issuer '" + cacert.getSubjectDN().getName() + "'");
                        OCSPSingleResponse sres = new OCSPSingleResponse(certId);
                        sres.setCertStatus(OCSPSingleResponse.CERTSTATUS_UNKNOWN);
                        res.addSingleResponse(sres);
                    } else {
                        OCSPSingleResponse sr = new OCSPSingleResponse(certId);
                        if (rci.getReason() > 0) {
                            OCSPRevokedInfo ori = new OCSPRevokedInfo();
                            ori.setRevocationTime(rci.getRevocationDate());
                            ori.setRevocationReason(rci.getReason());
                            sr.setCertStatus(OCSPSingleResponse.CERTSTATUS_REVOKED);                        
                            sr.setRevocationInfo(ori);
                        } else {
                            sr.setCertStatus(OCSPSingleResponse.CERTSTATUS_GOOD);
                        }
                        if (m_log.isDebugEnabled()) {
                            m_log.info("Adding status information for certificate with serial '"
                                       + certId.getCertificateSerial() + "'"
                                       + " from issuer '" + cacert.getSubjectDN().getName() + "'");
                        }
                        res.addSingleResponse(sr);
                    }
                }
                res.setStatus(OCSPResponse.SUCCESSFUL);
            }            
            res.sign(m_signkey, m_signcerts, "sha1withrsa");
            res.serializeTo(response.getOutputStream());
        } catch (OCSPException e) {
            /**
             * FIXME:
             * we only throw an exception but we should
             * return a proper OCSP exception to the caller
             */
            m_log.error("Unable to handle OCSP request.", e);            
            throw new ServletException(e.toString());
        } catch (Exception e) {
            /**
             * FIXME:
             * we only throw an exception but we should
             * return a OCSPInternalError to the caller
             */
            m_log.error("Unable to handle OCSP request.", e);
            throw new ServletException(e.toString());            
        }
        m_log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest request,  HttpServletResponse response) 
        throws IOException, ServletException {
        m_log.debug(">doGet()");
        /**
         * We only support POST operation, so return
         * an appropriate HTTP error code to caller.
         */
        m_log.debug("<doGet()");
    } // doGet

    /**
     * Prints debug info back to browser client
     **/
    private class Debug {
        final private ByteArrayOutputStream buffer;
        final private PrintStream printer;
        final private HttpServletRequest request;
        final private HttpServletResponse response;
        Debug(HttpServletRequest request, HttpServletResponse response){
            buffer=new ByteArrayOutputStream();
            printer=new PrintStream(buffer);
            this.request=request;
            this.response=response;
        }

        void printDebugInfo() throws IOException, ServletException {
            request.setAttribute("ErrorMessage",new String(buffer.toByteArray()));
            request.getRequestDispatcher("/error.jsp").forward(request, response);
        }

        void print(Object o) {
            printer.println(o);
        }
        void printMessage(String msg) {
            print("<p>"+msg);
        }
        void printInsertLineBreaks( byte[] bA ) throws Exception {
            BufferedReader br=new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(bA)) );
            while ( true ){
                String line=br.readLine();
                if (line==null)
                    break;
                print(line.toString()+"<br>");
            }
        }
        void takeCareOfException(Throwable t ) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            t.printStackTrace(new PrintStream(baos));
            print("<h4>Exception:</h4>");
            try {
                printInsertLineBreaks( baos.toByteArray() );
            } catch (Exception e) {
                e.printStackTrace(printer);
            }
            request.setAttribute("Exception", "true");
        }
    } // Debug

} // ScepServlet
