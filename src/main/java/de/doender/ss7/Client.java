package de.doender.ss7;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.SimpleLayout;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;

import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.ExchangeType;
import org.restcomm.protocols.ss7.m3ua.Functionality;
import org.restcomm.protocols.ss7.m3ua.IPSPType;
import org.restcomm.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.restcomm.protocols.ss7.m3ua.impl.parameter.NetworkAppearanceImpl;
import org.restcomm.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;
import org.restcomm.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.restcomm.protocols.ss7.map.MAPStackImpl;
import org.restcomm.protocols.ss7.map.api.*;
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.dialog.*;
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.map.api.primitives.*;
import org.restcomm.protocols.ss7.map.api.service.supplementary.*;
import org.restcomm.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.restcomm.protocols.ss7.sccp.*;
import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.BCDOddEncodingScheme;
import org.restcomm.protocols.ss7.sccp.impl.parameter.GlobalTitle0011Impl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle0011;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.tcap.TCAPStackImpl;
import org.restcomm.protocols.ss7.tcap.api.TCAPStack;
import org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;

import static org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY;

/**
 * Hello world!
 *
 */
public class Client implements MAPDialogListener, MAPServiceSupplementaryListener
{
    private static Logger rootLogger = Logger.getRootLogger();
    private static Logger logger = Logger.getLogger(Client.class);

    private ManagementImpl sctpManagement;

    private M3UAManagementImpl clientM3UAMgmt;

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
        this.initTCAP();
        this.initMAP();
    }

    private void initSCTP(IpChannelType channelType) throws java.io.IOException, java.lang.Exception {
        this.sctpManagement = new ManagementImpl("Client");
        this.sctpManagement.setSingleThread(true);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.removeAllResourses();

        this.sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ASSOCIATION_NAME, channelType, null);
    }


    private void initM3UA() throws java.lang.Exception {
        this.clientM3UAMgmt = new M3UAManagementImpl("client", "standaloness7", null);
        this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResourses();

        RoutingContext rc = factory.createRoutingContext(new long[] { 1001 });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

        this.clientM3UAMgmt.createAs("AS1", Functionality.AS, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 0, null);
        this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

        Asp asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

        clientM3UAMgmt.addRoute(SERVER_SPC, CLIENT_SPC, 3, "AS1", TrafficModeType.Loadshare);
        //this.clientM3UAMgmt.startAsp("ASP1");

        logger.debug("Initialized M3UA Stack");

    }

    private void initSCCP() throws java.lang.Exception {
        logger.debug("Initializing SCCP");
        this.sccpStack = new SccpStackImpl("MapLoadClientSccpStack", null);
        this.sccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);

        logger.debug("Starting stack and removing any resources");
        this.sccpStack.start();
        this.sccpStack.removeAllResourses();

        logger.debug("Adding Remote SPC");
        this.sccpStack.getSccpResource().addRemoteSpc(0, SERVER_SPC, 0, 0);
        logger.debug("Adding Remote SSN");
        this.sccpStack.getSccpResource().addRemoteSsn(0, SERVER_SPC, SSN, 0, false);

        logger.debug("Adding MTP3 SAP");
        // id, mtp3ID, OPC, NI, netID, localGtDigits;
        this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, 0, "49123456789");
        logger.debug("Adding MTP3 Destination");
        this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);

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

        this.mapStack = new MAPStackImpl("MapStack", this.tcapStack.getProvider());
        this.mapProvider = this.mapStack.getMAPProvider();

        this.mapProvider.addMAPDialogListener(this);
        this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);

        this.mapProvider.getMAPServiceSupplementary().acivate();

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
        // This error condition. Client should never receive the
        // ProcessUnstructuredSSRequestIndication
        logger.error(String.format("onProcessUnstructuredSSRequestIndication for Dialog=%d and invokeId=%d",
                procUnstrReqInd.getMAPDialog().getLocalDialogId(), procUnstrReqInd.getInvokeId()));
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


    public static void main( String[] args )
    {
        SimpleLayout layout = new SimpleLayout();
        ConsoleAppender consoleAppender = new ConsoleAppender( layout );
        rootLogger.addAppender( consoleAppender );
        rootLogger.setLevel(Level.DEBUG);
        IpChannelType channelType = IpChannelType.SCTP;

        final Client client = new Client();

        try {
            client.initializeStack(channelType);

            // Lets pause for 20 seconds so stacks are initialized properly
            Thread.sleep(10000);
            client.clientM3UAMgmt.start();
            client.clientM3UAMgmt.startAsp("ASP1");
            System.out.println(client.clientM3UAMgmt.getAppServers().get(0).getName());
            System.out.println(client.clientM3UAMgmt.getAppServers().get(0).isConnected());
            System.out.println(client.clientM3UAMgmt.getAppServers().get(0).isUp());
            Thread.sleep(20000);
            client.initiateUSSD();

        }
        catch (java.lang.Exception ex) {
            System.out.println(ex.toString());
            System.out.println("An exception occurred");
        }
    }
}
