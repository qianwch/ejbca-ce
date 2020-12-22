package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.junit.*;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa282_AdministratorRolesSupervisor extends WebTestBase {

    //Classes
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static RaWebHelper raWebHelper;
    private static AdminRolesHelper adminRolesHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    private static AddEndEntityHelper addEndEntityHelper;

    //Test Data
    private static class TestData {
        static final String CERTIFICATE_PROFILE_NAME_SUPERVISOR = "Supervisor";
        static final String CERTIFICATE_PROFILE_NAME_ENDUSER = "ENDUSER";
        static final List<String> SELECTED_AVAILABLE_BIT_LENGTHS = new ArrayList<>(Arrays.asList("1024 bits", "2048 bits", "4096 bits"));
        static final String VALIDITY_INPUT = "1y";
        static final String CA_NAME = "ManagementCA";
        static final String SELECTED_EXTENDED_KEY_USAGE = "Client Authentication";
        static final String END_ENTITY_PROFILE = "Supervisor";
        static final String ROLE_NAME = "Supervisor";
        static final String ROLE_TEMPLATE = "Supervisors";
        static final String USER_NAME = "Supervisor";
        static final String PASSWORD = "foo123";
        static final String KEY_ALGORITHM = "RSA 4096 bits";
        static final String COMMON_NAME = "Supervisor";
        static final Map<String, String> END_ENTITY_FIELDMAP = new HashMap<>();
        {
            END_ENTITY_FIELDMAP.put("Username", TestData.USER_NAME);
            END_ENTITY_FIELDMAP.put("Password (or Enrollment Code)", TestData.PASSWORD);
            END_ENTITY_FIELDMAP.put("Confirm Password", TestData.PASSWORD);
            END_ENTITY_FIELDMAP.put("CN, Common name", TestData.COMMON_NAME);
        }
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        // Init helpers
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
        adminRolesHelper = new AdminRolesHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // super
        afterClass();
    }

    @After
    public void afterTest() {
        // Remove generated artifacts
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE);
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        removeEndEntityByUsername(TestData.USER_NAME);
    }

    @Test
    public void test1_CreateCertificateProfile() {
        //When
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.cloneCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_ENDUSER, TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        //Then
        certificateProfileHelper.assertCertificateProfileNameExists(TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
    }

    @Test
    public void test2_EditCertificateProfileAndAssertSaved() {
        //when
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.cloneCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_ENDUSER, TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        certificateProfileHelper.editAvailableBitLengthsInCertificateProfile(TestData.SELECTED_AVAILABLE_BIT_LENGTHS);
        certificateProfileHelper.fillValidity(TestData.VALIDITY_INPUT);
        certificateProfileHelper.triggerPermissionsKeyUsageOverride();
        certificateProfileHelper.triggerX509v3ExtensionsUsagesKeyUsageNonRepudiation();
        certificateProfileHelper.selectExtendedKeyUsage(TestData.SELECTED_EXTENDED_KEY_USAGE);
        certificateProfileHelper.selectAvailableCa(TestData.CA_NAME);
        //then
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void test3_AddEndEntityProfileAndAssertSaved() {
        //when
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        //then
        endEntityProfileHelper.assertEndEntityProfileNameExists(TestData.END_ENTITY_PROFILE);
    }

    @Test
    public void test4_EditEndEntityProfileAndAssertSaved() {
        //when
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE);
        endEntityProfileHelper.selectDefaultCp(TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        endEntityProfileHelper.selectAvailableCp(TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        endEntityProfileHelper.selectDefaultCa(TestData.CA_NAME);
        endEntityProfileHelper.selectAvailableCa(TestData.CA_NAME);
        //then
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    @Ignore
    //Test incomplete.
    public void test5_() throws InterruptedException {
        //when
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.cloneCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_ENDUSER, TestData.CERTIFICATE_PROFILE_NAME_SUPERVISOR);
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        raWebHelper.openPage(getAdminWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE);
        raWebHelper.selectKeyPairGenerationOnServer();
        raWebHelper.selectKeyAlgorithm(TestData.KEY_ALGORITHM);
        raWebHelper.fillMakeRequestEditCommonName(TestData.COMMON_NAME);
        raWebHelper.fillUsername(TestData.USER_NAME);
        raWebHelper.fillEnrollUsernameAndCode(TestData.USER_NAME, TestData.PASSWORD);
        raWebHelper.clickDownloadPkcs12();
        //then

        //assert Supervisor.p12 is downloaded locally
        //remove p12
    }

    @Test
    public void test6_OpenAndAssertRolesManagementPageIsOpen() {
        adminRolesHelper.openPage(getAdminWebUrl());
    }

    @Test
    public void test7_AddRoleAndAssertExistsAndMessageDisplayed() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
    }

    @Test
    public void test8_OpenEditAccessRulesAndAssertDisplayed() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
    }

    @Test
    public void test9_AssertRoleTemplateSupervisorExists() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE);
        adminRolesHelper.assertAuthorizedCAsIsEnabled(true);
        adminRolesHelper.assertEndEntityRulesHasViewEndEntitiesAndViewHistorySelected();
        adminRolesHelper.assertEndEntityProfilesIsEnabled(true);
        adminRolesHelper.assertValidatorsIsEnabled(true);
        adminRolesHelper.assertInternalKeybindingRulesIsEnabled(true);
        adminRolesHelper.assertOtherRulesHasAllSelected();
        adminRolesHelper.saveAccessRule();
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.assertRoleTemplateHasSelectedName(TestData.ROLE_TEMPLATE);
    }

    @Test
    public void test10_UpdateCAAndEndEntityProfileInRoleAndAssertSaved() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate("Supervisors");
        adminRolesHelper.selectAvailableSingleCa("All");
        adminRolesHelper.selectAvailableSingleEndEntityProfile("All");
        adminRolesHelper.saveAccessRule();
    }

    @Test
    @Ignore
    // Test incomplete.
    public void test11_SearchForEndEntityByUserNameAndAssertCertificateExists() {
        //Add certificate
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE);
        addEndEntityHelper.fillFields(TestData.END_ENTITY_FIELDMAP);
        addEndEntityHelper.addEndEntity();
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.fillSearchCriteria(TestData.USER_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);
        searchEndEntitiesHelper.triggerSearchResultUsernameRowSelect(TestData.USER_NAME);
        searchEndEntitiesHelper.clickViewCertificateForRow(TestData.USER_NAME);
        //click on View button for certificate under actions for supervisor
        //Note down 'certificate serial number'
    }

    @Test
    @Ignore
    //Test incomplete.
    public void test12_() {
        //Add certificate
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditMembersPage(TestData.ROLE_NAME);
        //input certificate serial number
        // assert row content


    }

    @Test
    @Ignore
    //Test incomplete
    public void test13_() {

        //import supervisor.p12 to browser

    }

    @Test
    @Ignore
    //Test incomplete
    public void test14_() {

        //open incognito tab
        //choose Supervisor's EJBCA Sample ID
        //Assert message shown

    }

    @Test
    @Ignore
    //Test incomplete
    public void test15_() {
        // Open view Log
        //is 'current conditions' and 'search result' visible

    }

    @Test
    @Ignore
    //Test incomplete
    public void test16_() {
        //Choose an 'Event' which has a 'Certificate Authority' available
        //click on value for 'Certificate Authority'
        //Assert 'CA Certificate' is displayed

    }

    @Test
    @Ignore
    //Test incomplete
    public void test17_() {
        //Open view Log
        //Choose an 'Event with 'Certificate' available
        //Click on value for 'Certificate'
        //Assert 'View Certificate' page is displayed
    }

}
