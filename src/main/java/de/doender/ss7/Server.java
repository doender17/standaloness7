package de.doender.ss7;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.SimpleLayout;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.restcomm.protocols.ss7.indicator.NatureOfAddress;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;

import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.ExchangeType;
import org.restcomm.protocols.ss7.m3ua.Functionality;
import org.restcomm.protocols.ss7.m3ua.IPSPType;
import org.restcomm.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.restcomm.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;
import org.restcomm.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.restcomm.protocols.ss7.map.MAPStackImpl;
import org.restcomm.protocols.ss7.map.api.*;
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.dialog.*;
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.map.api.primitives.*;
import org.restcomm.protocols.ss7.map.api.service.mobility.MAPDialogMobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.MAPServiceMobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.ForwardCheckSSIndicationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.ResetRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.CheckImeiRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.CheckImeiResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.*;
import org.restcomm.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeRequest_Mobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeResponse_Mobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.*;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.*;
import org.restcomm.protocols.ss7.map.api.service.supplementary.*;
import org.restcomm.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.restcomm.protocols.ss7.sccp.*;
import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.BCDOddEncodingScheme;
import org.restcomm.protocols.ss7.sccp.impl.parameter.GlobalTitle0011Impl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.parameter.EncodingScheme;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle0011;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.tcap.TCAPStackImpl;
import org.restcomm.protocols.ss7.tcap.api.TCAPStack;
import org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;

import java.util.ArrayList;

import static org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY;

/**
 * Hello world!
 *
 */
public class Server implements MAPDialogListener, MAPServiceSupplementaryListener, MAPServiceMobilityListener
{
    private static Logger rootLogger = Logger.getRootLogger();
    private static Logger logger = Logger.getLogger(Client.class);

    private ManagementImpl sctpManagement;

    private M3UAManagementImpl serverM3UAMgmt;

    private SccpStackImpl sccpStack;
    private SccpResource sccpResource;

    private TCAPStack tcapStack;

    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;

    private final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    private final String CLIENT_IP="192.168.50.17";
    private final int CLIENT_PORT=10111;
    private final String CLIENT_ASSOCIATION_NAME = "client_association";
    private final int CLIENT_SPC = 500;
    private final int NETWORK_INDICATOR = 2;
    private final int SERVICE_INIDCATOR = 3; // SCCP
    private final int SSN = 8;

    private final String SERVER_IP="192.168.50.18";
    private final int SERVER_PORT=10112;
    private final String SERVER_NAME = "server";
    private final String SERVER_ASSOCIATION_NAME = "server_association";
    private final int SERVER_SPC = 501;

    private final GlobalTitle0011Impl clientGT = new GlobalTitle0011Impl("49123456789", 0, new BCDOddEncodingScheme(), ISDN_TELEPHONY);
    private final GlobalTitle0011Impl serverGT = new GlobalTitle0011Impl("49987654321", 0, new BCDOddEncodingScheme(), ISDN_TELEPHONY);
    private final SccpAddress SCCP_CLIENT_ADDRESS = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, clientGT, CLIENT_SPC, SSN);
    private final SccpAddress SCCP_SERVER_ADDRESS = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, serverGT, SERVER_SPC, SSN);

    protected void initializeStack(IpChannelType ipchanneltype) throws java.lang.Exception {
        this.initSCTP(ipchanneltype);
        this.initM3UA();
        this.initSCCP();
        //this.initTCAP();
        this.initMAP();
        serverM3UAMgmt.startAsp("RASP1");
    }

    private void initSCTP(IpChannelType channelType) throws java.io.IOException, java.lang.Exception {
        this.sctpManagement = new ManagementImpl("Client");
        this.sctpManagement.setSingleThread(true);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.removeAllResourses();

        this.sctpManagement.addServer(SERVER_NAME, SERVER_IP, SERVER_PORT, channelType, null);
        this.sctpManagement.addServerAssociation(CLIENT_IP, CLIENT_PORT, SERVER_NAME, SERVER_ASSOCIATION_NAME, channelType);

        this.sctpManagement.startServer(SERVER_NAME);
    }


    private void initM3UA() throws java.lang.Exception {
        this.serverM3UAMgmt = new M3UAManagementImpl("server", "standaloness7", null);
        this.serverM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.serverM3UAMgmt.start();
        this.serverM3UAMgmt.removeAllResourses();

        RoutingContext rc = factory.createRoutingContext(new long[] { 1001 });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

        this.serverM3UAMgmt.createAs("RAS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 1, null);
        this.serverM3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);

        Asp asp = this.serverM3UAMgmt.assignAspToAs("RAS1", "RASP1");

        serverM3UAMgmt.addRoute(CLIENT_SPC, SERVER_SPC, 3, "RAS1");

        logger.debug("Initialized M3UA Stack");

    }

    private void initSCCP() throws java.lang.Exception {
        logger.debug("Initializing SCCP");
        this.sccpStack = new SccpStackImpl("MapLoadServerSccpStack");
        this.sccpStack.setMtp3UserPart(1, this.serverM3UAMgmt);

        logger.debug("Starting stack and removing any resources");
        this.sccpStack.start();
        this.sccpStack.removeAllResourses();

        logger.debug("Adding Remote SPC");
        this.sccpStack.getSccpResource().addRemoteSpc(0, CLIENT_SPC, 0, 0);
        logger.debug("Adding Remote SSN");
        this.sccpStack.getSccpResource().addRemoteSsn(0, CLIENT_SPC, SSN, 0, false);

        logger.debug("Adding MTP3 SAP");
        // id, mtp3ID, OPC, NI, netID, localGtDigits;
        this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, SERVER_SPC, NETWORK_INDICATOR, 0, "49987654321");
        logger.debug("Adding MTP3 Destination");
        this.sccpStack.getRouter().addMtp3Destination(1, 1, CLIENT_SPC, CLIENT_SPC, 0, 255, 255);

        org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl fact = new org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl();
        EncodingScheme ec = new BCDOddEncodingScheme();
        GlobalTitle gt1 = fact.createGlobalTitle("-", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt2 = fact.createGlobalTitle("-", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, SERVER_SPC, 0);
        sccpStack.getRouter().addRoutingAddress(1, localAddress);
        SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, CLIENT_SPC, 0);
        sccpStack.getRouter().addRoutingAddress(2, remoteAddress);

        GlobalTitle gt = fact.createGlobalTitle("*", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0,0);
        // 1: Rule Number, 2: RuleType, 3: LoadSharingAlgo, 4: Origin, 5: pattern, 6: mask, 7: primaryAddress, 8: secondaryAddress (-1=none),
        // 9: newCallingPartyAddressId, 10: networkId, 11: callingParty pattern (A-Number based rules)
        sccpStack.getRouter().addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE, pattern, "K", 1, -1, null, 0, pattern);
        sccpStack.getRouter().addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.LOCAL, pattern, "K", 2, -1, null, 0, pattern);
        logger.debug("SCCP Stack initialized");
    }

    private void initTCAP() throws java.lang.Exception {
        logger.debug("Initializing TCAP Stack ....");
        this.tcapStack = new TCAPStackImpl("ClientTCAP", this.sccpStack.getSccpProvider(), SSN);
        this.tcapStack.start();

        this.tcapStack.setDialogIdleTimeout(60000);
        this.tcapStack.setInvokeTimeout(30000);
        this.tcapStack.setMaxDialogs(2000);
        logger.debug("Initialized TCAP Stack ....");
    }

    private void initMAP() throws java.lang.Exception {
        logger.debug("Initializing MAP Stack ....");

        this.mapStack = new MAPStackImpl("MapStack", this.sccpStack.getSccpProvider(), SSN);
        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceMobility().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSupplementary().acivate();
        this.mapProvider.getMAPServiceMobility().acivate();

        this.mapStack.start();
        logger.debug("Initialized MAP Stack ....");
    }

    private void initiateUSSD() throws MAPException {

        // First create Dialog
        MAPParameterFactory mapParameterFactory = this.mapProvider.getMAPParameterFactory();
        ISDNAddressString origReference = mapParameterFactory.createISDNAddressString(AddressNature.international_number, NumberingPlan.land_mobile, "26220");
        ISDNAddressString destReference = mapParameterFactory.createISDNAddressString(AddressNature.international_number, NumberingPlan.land_mobile, "26203");
        MAPDialogSupplementary mapDialog = this.mapProvider.getMAPServiceSupplementary().createNewDialog(
                MAPApplicationContext.getInstance(MAPApplicationContextName.networkUnstructuredSsContext,
                        MAPApplicationContextVersion.version2), SCCP_CLIENT_ADDRESS, origReference, SCCP_SERVER_ADDRESS, destReference);

        CBSDataCodingSchemeImpl cbsDataCodingScheme = new CBSDataCodingSchemeImpl(0x0f);

        // USSD String: *125*+31628839999#
        // The Charset is null, here we let system use default Charset (UTF-7 as
        // explained in GSM 03.38. However if MAP User wants, it can set its own
        // impl of Charset
        USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("*125*+31628839999#");

        ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

        mapDialog.addProcessUnstructuredSSRequest(cbsDataCodingScheme, ussdString, null, msisdn);

        // This will initiate the TC-BEGIN with INVOKE component
        mapDialog.send();
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogAccept(
     * org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), extensionContainer));
        }
    }

    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
                               ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer)
    {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogReject for DialogId=%d MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), extensionContainer));
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogClose(org
     * .mobicents.protocols.ss7.map.api.MAPDialog)
     */
    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogNotice(
     * org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic)
     */
    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        logger.error(String.format("onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogProviderAbort
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
                                      MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
        logger.error(String
                .format("onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
                        mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRelease
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequest
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String
                    .format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
                            mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
    }


    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequestEricsson
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
     * org.mobicents.protocols.ss7.map.api.primitives.IMSI,
     * org.mobicents.protocols.ss7.map.api.primitives.AddressString)
     */
    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                        AddressString eriMsisdn, AddressString eriVlrNo) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
                    mapDialog.getLocalDialogId(), destReference, origReference));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogTimeout
     * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    public void onDialogTimeout(MAPDialog mapDialog) {
        logger.error(String.format("onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId()));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogUserAbort
     * (org.mobicents.protocols.ss7.map.api.MAPDialog,
     * org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice,
     * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
                                  MAPExtensionContainer extensionContainer) {
        logger.error(String.format("onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), userReason, extensionContainer));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSRequest(org.mobicents
     * .protocols.ss7.map.api.service
     * .supplementary.ProcessUnstructuredSSRequest)
     */
    public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest procUnstrReqInd) {

        long invokeId = procUnstrReqInd.getInvokeId();

        CBSDataCodingSchemeImpl cbsDataCodingScheme = new CBSDataCodingSchemeImpl(0x0f);

        MAPDialogSupplementary dialog = procUnstrReqInd.getMAPDialog();

        dialog.setUserObject(invokeId);

        ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory().createISDNAddressString(
                AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

        try {
            USSDString ussdStringObj = this.mapProvider.getMAPParameterFactory().createUSSDString("USSD String : Hello World <CR> 1. Balance <CR> 2. Texts Remaining");

            dialog.addUnstructuredSSRequest(cbsDataCodingScheme, ussdStringObj, null, msisdn);

            dialog.send();
        }
        catch (MAPException e)
        {
            logger.debug("Error in replying to USSD: " + e.toString());
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onProcessUnstructuredSSResponse(org.mobicents
     * .protocols.ss7.map.api.service
     * .supplementary.ProcessUnstructuredSSResponse)
     */
    public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse procUnstrResInd) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Rx ProcessUnstructuredSSResponseIndication.  USSD String=%s", procUnstrResInd
                    .getUSSDString().getEncodedString()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSNotifyRequest(org.mobicents
     * .protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest)
     */
    public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest unstrNotifyInd) {
        // This error condition. Client should never receive the
        // UnstructuredSSNotifyRequestIndication
        logger.error(String.format("onUnstructuredSSNotifyRequestIndication for Dialog=%d and invokeId=%d",
                unstrNotifyInd.getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSNotifyResponse(org.mobicents
     * .protocols.ss7.map.api.service
     * .supplementary.UnstructuredSSNotifyResponse)
     */
    public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {
        // This error condition. Client should never receive the
        // UnstructuredSSNotifyRequestIndication
        logger.error(String.format("onUnstructuredSSNotifyResponseIndication for Dialog=%d and invokeId=%d",
                unstrNotifyInd.getMAPDialog().getLocalDialogId(), unstrNotifyInd.getInvokeId()));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSRequest(org.mobicents.protocols
     * .ss7.map.api.service.supplementary.UnstructuredSSRequest)
     */
    public void onUnstructuredSSRequest(UnstructuredSSRequest unstrReqInd) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Rx UnstructuredSSRequestIndication. USSD String=%s ", unstrReqInd
                    .getUSSDString().getEncodedString()));
        }

        MAPDialogSupplementary mapDialog = unstrReqInd.getMAPDialog();

        try {
            CBSDataCodingSchemeImpl cbsDataCodingScheme = new CBSDataCodingSchemeImpl(0x0f);

            USSDString ussdString = this.mapProvider.getMAPParameterFactory().createUSSDString("1", cbsDataCodingScheme, null);

            AddressString msisdn = this.mapProvider.getMAPParameterFactory().createAddressString(
                    AddressNature.international_number, NumberingPlan.ISDN, "31628838002");

            mapDialog.addUnstructuredSSResponse(unstrReqInd.getInvokeId(), cbsDataCodingScheme, ussdString);
            mapDialog.send();

        } catch (MAPException e) {
            logger.error(String.format("Error while sending UnstructuredSSResponse for Dialog=%d",
                    mapDialog.getLocalDialogId()));
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see org.mobicents.protocols.ss7.map.api.service.supplementary.
     * MAPServiceSupplementaryListener
     * #onUnstructuredSSResponse(org.mobicents.protocols
     * .ss7.map.api.service.supplementary.UnstructuredSSResponse)
     */
    public void onUnstructuredSSResponse(UnstructuredSSResponse unstrResInd) {
        // This error condition. Client should never receive the
        // UnstructuredSSResponseIndication
        logger.error(String.format("onUnstructuredSSResponseIndication for Dialog=%d and invokeId=%d", unstrResInd
                .getMAPDialog().getLocalDialogId(), unstrResInd.getInvokeId()));
    }

    public void onRegisterPasswordRequest(RegisterPasswordRequest request) {};

    public void onRegisterPasswordResponse(RegisterPasswordResponse response) {};

    public void onGetPasswordResponse(GetPasswordResponse response) {};

    public void onGetPasswordRequest(GetPasswordRequest request) {};

    public void onInterrogateSSRequest(InterrogateSSRequest request) {};

    public void onInterrogateSSResponse(InterrogateSSResponse response) {};

    public void onRegisterSSRequest(RegisterSSRequest request) {};

    public void onRegisterSSResponse(RegisterSSResponse response) {};

    public void onEraseSSRequest(EraseSSRequest request) {};

    public void onEraseSSResponse(EraseSSResponse response) {};

    public void onActivateSSRequest(ActivateSSRequest request) {};

    public void onActivateSSResponse(ActivateSSResponse response) {};

    public void onDeactivateSSRequest(DeactivateSSRequest request) {};

    public void onDeactivateSSResponse(DeactivateSSResponse response) {};

    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        logger.error(String.format("onRejectComponent for Dialog=%d and invokeId=%d",
                mapDialog.getLocalDialogId(), invokeId));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onErrorComponent
     * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
     * org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage)
     */
    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        logger.error(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onInvokeTimeout
     * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long)
     */
    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        logger.error(String.format("onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(), invokeId));
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onMAPMessage(org
     * .mobicents.protocols.ss7.map.api.MAPMessage)
     */
    public void onMAPMessage(MAPMessage arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest updateLocationRequest) {
        MAPParameterFactory mapParameterFactory = this.mapProvider.getMAPParameterFactory();
        MAPServiceMobility mapServiceMobility = this.mapProvider.getMAPServiceMobility();
        mapServiceMobility.acivate();

        MAPDialogMobility mapDialog = updateLocationRequest.getMAPDialog();

        ISDNAddressString msisdn = mapParameterFactory.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, "4915775405009");
        Category category = mapParameterFactory.createCategory(10);
        SubscriberStatus subStatus = SubscriberStatus.getInstance(0);
        ExtTeleserviceCode tsTelephony = mapParameterFactory.createExtTeleserviceCode(TeleserviceCodeValue.telephony);
        ExtTeleserviceCode tsEmergency = mapParameterFactory.createExtTeleserviceCode(TeleserviceCodeValue.emergencyCalls);
        ExtTeleserviceCode tsSMSMT = mapParameterFactory.createExtTeleserviceCode(TeleserviceCodeValue.shortMessageMO_PP);
        ExtTeleserviceCode tsSMSMO = mapParameterFactory.createExtTeleserviceCode(TeleserviceCodeValue.shortMessageMT_PP);
        ArrayList<ExtTeleserviceCode> teleservices = new ArrayList<>();
        teleservices.add(tsTelephony); teleservices.add(tsEmergency); teleservices.add(tsSMSMT); teleservices.add(tsSMSMO);

        try {
            mapDialog.addInsertSubscriberDataRequest(updateLocationRequest.getImsi(), msisdn, category, subStatus, null, teleservices, null, null, false, null, null, null,null);
        } catch (MAPException e) {
            e.printStackTrace();
        }

        try {
            mapDialog.send();
        } catch (MAPException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse updateLocationResponse) {

    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest cancelLocationRequest) {

    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse cancelLocationResponse) {

    }

    @Override
    public void onSendIdentificationRequest(SendIdentificationRequest sendIdentificationRequest) {

    }

    @Override
    public void onSendIdentificationResponse(SendIdentificationResponse sendIdentificationResponse) {

    }

    @Override
    public void onUpdateGprsLocationRequest(UpdateGprsLocationRequest updateGprsLocationRequest) {

    }

    @Override
    public void onUpdateGprsLocationResponse(UpdateGprsLocationResponse updateGprsLocationResponse) {

    }

    @Override
    public void onPurgeMSRequest(PurgeMSRequest purgeMSRequest) {

    }

    @Override
    public void onPurgeMSResponse(PurgeMSResponse purgeMSResponse) {

    }

    @Override
    public void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest sendAuthenticationInfoRequest) {

    }

    @Override
    public void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse sendAuthenticationInfoResponse) {

    }

    @Override
    public void onAuthenticationFailureReportRequest(AuthenticationFailureReportRequest authenticationFailureReportRequest) {

    }

    @Override
    public void onAuthenticationFailureReportResponse(AuthenticationFailureReportResponse authenticationFailureReportResponse) {

    }

    @Override
    public void onResetRequest(ResetRequest resetRequest) {

    }

    @Override
    public void onForwardCheckSSIndicationRequest(ForwardCheckSSIndicationRequest forwardCheckSSIndicationRequest) {

    }

    @Override
    public void onRestoreDataRequest(RestoreDataRequest restoreDataRequest) {

    }

    @Override
    public void onRestoreDataResponse(RestoreDataResponse restoreDataResponse) {

    }

    @Override
    public void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest anyTimeInterrogationRequest) {

    }

    @Override
    public void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse anyTimeInterrogationResponse) {

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationRequest(AnyTimeSubscriptionInterrogationRequest anyTimeSubscriptionInterrogationRequest) {

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationResponse(AnyTimeSubscriptionInterrogationResponse anyTimeSubscriptionInterrogationResponse) {

    }

    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest provideSubscriberInfoRequest) {

    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse provideSubscriberInfoResponse) {

    }

    @Override
    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest insertSubscriberDataRequest) {

    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse insertSubscriberDataResponse) {
        MAPParameterFactory mapParameterFactory = this.mapProvider.getMAPParameterFactory();
        MAPDialogMobility mapDialog = insertSubscriberDataResponse.getMAPDialog();

        ISDNAddressString hlrAddr = mapParameterFactory.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, "491770020044");
        try {
            mapDialog.addUpdateLocationResponse(0l, hlrAddr, null, true, true);
        } catch (MAPException e) {
            e.printStackTrace();
        }

        try {
            // if set to false, messages will still be sent.
            mapDialog.closeDelayed(false);
        } catch (MAPException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest deleteSubscriberDataRequest) {

    }

    @Override
    public void onDeleteSubscriberDataResponse(DeleteSubscriberDataResponse deleteSubscriberDataResponse) {

    }

    @Override
    public void onCheckImeiRequest(CheckImeiRequest checkImeiRequest) {

    }

    @Override
    public void onCheckImeiResponse(CheckImeiResponse checkImeiResponse) {

    }

    @Override
    public void onActivateTraceModeRequest_Mobility(ActivateTraceModeRequest_Mobility activateTraceModeRequest_mobility) {

    }

    @Override
    public void onActivateTraceModeResponse_Mobility(ActivateTraceModeResponse_Mobility activateTraceModeResponse_mobility) {

    }


    public static void main( String[] args )
    {
        SimpleLayout layout = new SimpleLayout();
        ConsoleAppender consoleAppender = new ConsoleAppender( layout );
        rootLogger.addAppender( consoleAppender );
        rootLogger.setLevel(Level.DEBUG);
        IpChannelType channelType = IpChannelType.SCTP;

        final Server server = new Server();

        try {
            server.initializeStack(channelType);
            Thread.sleep(10000);
            server.serverM3UAMgmt.start();
            server.serverM3UAMgmt.startAsp("RASP1");

            // Lets pause for 20 seconds so stacks are initialized properly
            // Thread.sleep(10000);
        }
        catch (java.lang.Exception ex) {
            System.out.println(ex.toString());
            System.out.println("An exception occurred");
        }
    }


}
