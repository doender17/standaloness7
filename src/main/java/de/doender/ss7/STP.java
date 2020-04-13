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
 * STP that will route messages between the client and the server
 *
 */
public class STP
{
    private static Logger rootLogger = Logger.getRootLogger();
    private static Logger logger = Logger.getLogger(Client.class);

    private ManagementImpl sctpManagement;

    private M3UAManagementImpl serverM3UAMgmt;

    private SccpStackImpl sccpStack;

    private final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    private final int NETWORK_INDICATOR = 2;
    private final int SERVICE_INIDCATOR = 3; // SCCP

    private final String STP_IP="192.168.50.17";
    private final String VLR_IP="192.168.50.17";
    private final String HLR_IP="192.168.50.17";
    private final int VLR_STP_PORT=20111;
    private final int HLR_STP_PORT=20112;
    private final int STP_VLR_PORT=20211;
    private final int STP_HLR_PORT=20212;
    private final String SCTP_VLR_NAME="vlr_sctp";
    private final String SCTP_HLR_NAME="hlr_sctp";
    private final String VLR_ASSOCIATION_NAME="vlr_association";
    private final String HLR_ASSOCIATION_NAME="hlr_association";

    private final int VLR_SPC = 500;
    private final int HLR_SPC = 501;
    private final int STP_SPC = 520;
    private final int VLR_SSN = 7;
    private final int HLR_SSN = 6;

    private SccpAddress SCCP_VLR_ADDRESS;
    private SccpAddress SCCP_HLR_ADDRESS;

    protected void initializeStack(IpChannelType ipchanneltype) throws java.lang.Exception {
        this.initSCTP(ipchanneltype);
        this.initM3UA();
        this.initSCCP();
        serverM3UAMgmt.startAsp("VLRASP");
        serverM3UAMgmt.startAsp("HLRASP");
    }

    private void initSCTP(IpChannelType channelType) throws java.io.IOException, java.lang.Exception {
        this.sctpManagement = new ManagementImpl("stp");
        this.sctpManagement.setSingleThread(true);
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.removeAllResourses();

        this.sctpManagement.addServer(SCTP_VLR_NAME, STP_IP, STP_VLR_PORT, channelType, null);
        this.sctpManagement.addServerAssociation(VLR_IP, VLR_STP_PORT, SCTP_VLR_NAME, VLR_ASSOCIATION_NAME, channelType);
        this.sctpManagement.startServer(SCTP_VLR_NAME);

        this.sctpManagement.addServer(SCTP_HLR_NAME, STP_IP, STP_HLR_PORT, channelType, null);
        this.sctpManagement.addServerAssociation(HLR_IP, HLR_STP_PORT, SCTP_HLR_NAME, HLR_ASSOCIATION_NAME, channelType);
        this.sctpManagement.startServer(SCTP_HLR_NAME);
    }


    private void initM3UA() throws java.lang.Exception {
        this.serverM3UAMgmt = new M3UAManagementImpl("server", "standaloness7", null);
        this.serverM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.serverM3UAMgmt.start();
        this.serverM3UAMgmt.removeAllResourses();

        RoutingContext rc = factory.createRoutingContext(new long[] { 1001 });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

        this.serverM3UAMgmt.createAs("VLRAS", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 1, null);
        this.serverM3UAMgmt.createAspFactory("VLRASP", VLR_ASSOCIATION_NAME);
        Asp VLRAsp = this.serverM3UAMgmt.assignAspToAs("VLRAS", "VLRASP");
        serverM3UAMgmt.addRoute(VLR_SPC, STP_SPC, 3, "VLRAS");

        this.serverM3UAMgmt.createAs("HLRAS", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 1, null);
        this.serverM3UAMgmt.createAspFactory("HLRASP", HLR_ASSOCIATION_NAME);
        Asp HLRAsp = this.serverM3UAMgmt.assignAspToAs("HLRAS", "HLRASP");
        serverM3UAMgmt.addRoute(HLR_SPC, STP_SPC, 3, "HLRAS");

        logger.debug("Initialized M3UA Stack");
    }

    private void initSCCP() throws java.lang.Exception {
        logger.debug("Initializing SCCP");
        this.sccpStack = new SccpStackImpl("MapLoadServerSccpStack");
        this.sccpStack.setMtp3UserPart(1, this.serverM3UAMgmt);

        logger.debug("Starting stack and removing any resources");
        this.sccpStack.start();
        this.sccpStack.removeAllResourses();

        logger.debug("Adding VLR SPC");
        this.sccpStack.getSccpResource().addRemoteSpc(0, VLR_SPC, 0, 0);
        logger.debug("Adding VLR SSN");
        this.sccpStack.getSccpResource().addRemoteSsn(0, VLR_SPC, VLR_SSN, 0, false);

        logger.debug("Adding HLR SPC");
        this.sccpStack.getSccpResource().addRemoteSpc(1, HLR_SPC, 0, 0);
        logger.debug("Adding HLR SSN");
        this.sccpStack.getSccpResource().addRemoteSsn(1, HLR_SPC, HLR_SSN, 0, false);

        logger.debug("Adding MTP3 SAP");
        // id, mtp3ID, OPC, NI, netID, localGtDigits;
        this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, STP_SPC, NETWORK_INDICATOR, 0, null);
        logger.debug("Adding MTP3 Destination");
        this.sccpStack.getRouter().addMtp3Destination(1, 1, VLR_SPC, VLR_SPC, 0, 255, 255);
        this.sccpStack.getRouter().addMtp3Destination(1, 2, HLR_SPC, HLR_SPC, 0, 255, 255);

        org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl fact = new org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl();
        EncodingScheme ec = new BCDOddEncodingScheme();
        // HLR address
        GlobalTitle hlrGT = fact.createGlobalTitle("49987654321", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SCCP_HLR_ADDRESS = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, hlrGT, 0, 6);
        // VLR address
        GlobalTitle vlrGT = fact.createGlobalTitle("49123456789", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SCCP_VLR_ADDRESS = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, vlrGT, 0, 7);

        // SCCP global title translations
        // Rules consists of a match part and a translate part
        // First we configure that anything coming in from remote to the HLR GT and SSN 6 (HLR) will be accepted and delivered to the local PC
        // Match part:
        // Assume we will listen on GT prefix 4998765432, and VLR only
        GlobalTitle hlrPatternGT = fact.createGlobalTitle("4998765432*", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress hlrPattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, hlrPatternGT, 0,6);
        // Translate part:
        GlobalTitle gt1 = fact.createGlobalTitle("-", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress hlrAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, HLR_SPC, 0);
        // We add this to the router, so we can use it as the primary or secondary Address for the rule
        sccpStack.getRouter().addRoutingAddress(1, hlrAddress);
        // Now we add all this to the router, important is parameter 5 : pattern and parameter 7: primaryAddress (which is the index to the localAddress above)
        // 1: Rule Number, 2: RuleType, 3: LoadSharingAlgo, 4: Origin, 5: pattern, 6: mask, 7: primaryAddress, 8: secondaryAddress (-1=none),
        // 9: newCallingPartyAddressId, 10: networkId, 11: callingParty pattern (A-Number based rules)
        sccpStack.getRouter().addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE, hlrPattern, "K", 1, -1, null, 0, null);

        GlobalTitle vlrPatternGT = fact.createGlobalTitle("4912345678*", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress vlrPattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, vlrPatternGT, 0,7);
        // Translate part:
        GlobalTitle gt2 = fact.createGlobalTitle("-", 0, ISDN_TELEPHONY, ec, NatureOfAddress.INTERNATIONAL);
        SccpAddress vlrAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, VLR_SPC, 0);
        // We add this to the router, so we can use it as the primary or secondary Address for the rule
        sccpStack.getRouter().addRoutingAddress(2, vlrAddress);
        // Now we add all this to the router, important is parameter 5 : pattern and parameter 7: primaryAddress (which is the index to the localAddress above)
        // 1: Rule Number, 2: RuleType, 3: LoadSharingAlgo, 4: Origin, 5: pattern, 6: mask, 7: primaryAddress, 8: secondaryAddress (-1=none),
        // 9: newCallingPartyAddressId, 10: networkId, 11: callingParty pattern (A-Number based rules)
        sccpStack.getRouter().addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE, vlrPattern, "K", 2, -1, null, 0, null);

        logger.debug("SCCP Stack initialized");
    }

    public static void main( String[] args )
    {
        SimpleLayout layout = new SimpleLayout();
        ConsoleAppender consoleAppender = new ConsoleAppender( layout );
        rootLogger.addAppender( consoleAppender );
        rootLogger.setLevel(Level.TRACE);
        IpChannelType channelType = IpChannelType.SCTP;

        final STP stp = new STP();

        try {
            stp.initializeStack(channelType);
            Thread.sleep(10000);
        }
        catch (java.lang.Exception ex) {
            System.out.println(ex.toString());
            System.out.println("An exception occurred");
        }
    }


}
