package se.anatom.ejbca.ca.store.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import junit.framework.*;

/**
 *
 * @version $Id: TestRunner.java,v 1.3.6.1 2003-09-09 20:10:00 anatom Exp $
 */
public class TestRunner extends Object {

    private static Logger log = Logger.getLogger(TestRunner.class);

    public static void main (String[] args) {
        BasicConfigurator.configure();
        junit.textui.TestRunner.run (suite());
    }

    private void cleanUp() {
        log.debug(">cleanUp()");
        log.debug("<cleanUp()");
    }

    public static Test suite ( ) {
        log.debug(">suite()");

        TestSuite suite = new TestSuite();
        suite.addTest( new TestSuite( TestCertificateData.class ));
        suite.addTest( new TestSuite( TestCertificateRetrival.class ));
        //suite.addTest( new TestSuite( TestPublisher.class ));

        log.debug("<suite()");
        return suite;
    }
}
