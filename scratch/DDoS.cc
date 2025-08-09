#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/internet-module.h"
#include "ns3/nr-module.h"
#include "ns3/ipv4-flow-classifier.h"
#include <ns3/antenna-module.h>
#include "ns3/udp-client-server-helper.h"
#include "ns3/nr-point-to-point-epc-helper.h"
#include "ns3/point-to-point-helper.h"
#include <ns3/buildings-helper.h>
#include <ns3/nr-phy.h> // Include necessary for NrGnbPhy

// Headers needed for connectivity check
#include <map>
#include <iomanip> // For std::hex/dec output formatting
#include <vector>  // For attacker/victim lists
#include <set>     // For easy lookup

#include <iostream>

/*
    DDos attack done on fap unit uplink channel
    so, legitimate ues when send their packets to fap than due to
    uplink buffer being congested there packets are dropped and cant
    be scheduled.

*/
using namespace ns3;

// *** Helper function to check if an INDEX is present in a vector of indices ***
bool IsIndexInList(uint16_t indexToCheck, const std::vector<uint16_t>& indexList)
{
    for (uint16_t item : indexList)
    {
        if (indexToCheck == item)
        {
            return true;
        }
    }
    return false;
}

// *** Helper function to check if an IP ADDRESS belongs to a UE in a specific index list ***
// (Renamed from IsInList)
bool IsAddressInList(ns3::Ipv4Address addrToCheck,
                     const ns3::Ipv4InterfaceContainer& ueIpIfContainer, // Pass the IP container
                     const std::vector<uint16_t>& indicesToCheck, // List of UE indices to check
                     const ns3::NodeContainer& /* ueNodes */) // ueNodes isn't strictly needed here anymore
{
    for (uint16_t index : indicesToCheck)
    {
        // Ensure the index is valid for the IP interface container
        if (index < ueIpIfContainer.GetN())
        {
             // Get the IP address of the UE at the specified index within the container
             ns3::Ipv4Address ueAddr = ueIpIfContainer.GetAddress(index);
             if (addrToCheck == ueAddr)
             {
                 // The address matches the IP of a UE in the list
                 return true;
             }
        }
    }
    // The address was not found among the specified UEs
    return false;
}

int main(int argc, char *argv[])
{
    // Enable logging for the animation interface
    // LogComponentEnable("AnimationInterface", LOG_LEVEL_INFO); // Uncomment for NetAnim logging

    // --- Simulation Parameters ---
    double frequency = 28e9;
    double bandwidth = 100e6;
    double hBS = 25;              // Macro gNB height
    double hUT = 1.5;             // UE antenna height
    double speed = 1;
    double txPowerMacro = 40.0;   // Macro gNB Tx Power in dBm
    bool mobility = false;        // Keep mobility false for predictable connections
    BandwidthPartInfo::Scenario scenario = BandwidthPartInfo::UMa;
    uint16_t numUes = 15;    //number of ues
    uint16_t numMacroGnb = 2;
    Time simStopTime = Seconds(40.0); // Total simulation time
    double ueTxPower = 23.0;      // Example UE Tx Power in dBm

    // --- FAP Parameters ---
    uint16_t numFaps = 2;
    double hFAP = 5.0;            // FAP height (lower)
    double txPowerFAP = 20.0;     // FAP Tx Power in dBm (lower)

    // --- Application Ports ---
    uint16_t ulPort = 20000; // Legitimate Uplink (Also target for attack flood destination server)
    uint16_t dlPort = 10000; // Legitimate Downlink

    // --- DDoS Attack Parameters (Flooding FAP Uplink Radio Resources) ---
    std::vector<uint16_t> attackerUeIndices = {3, 4}; // UEs launching the attack (placed near FAPs)
    std::vector<uint16_t> fapLegitUeIndices = {0, 1}; // Legitimate UEs near FAPs to observe impact
    std::vector<uint16_t> macroLegitUeIndices = {2, 5, 6}; // Other legitimate UEs (assumed near Macro)

    Time ddosStartTime = Seconds(10.0);        // When the attack begins
    Time ddosStopTime = Seconds(25.0);         // When the attack ends
    // NOTE: Interval needs tuning based on packet size and expected PHY rate.
    // Start with a very small value. If sim runs too slow or crashes, increase it.
    Time attackerInterval = MicroSeconds(20);  // Attack packet interval (VERY HIGH RATE!) Aim to saturate uplink.
    uint32_t attackerPacketSize = 1024;        // Attack packet size

    // --- Setup ---
    NodeContainer vehicles;         // UEs
    NodeContainer macroGnbNodes;    // Macro gNBs
    NodeContainer fapNodes;         // FAP nodes
    vehicles.Create(numUes);
    macroGnbNodes.Create(numMacroGnb);
    fapNodes.Create(numFaps);

    // --- Mobility ---
    NS_ASSERT_MSG(!mobility, "Mobility must be disabled for predictable UE-FAP association in this scenario");
    // Macro gNB Mobility (Fixed)
    Ptr<ListPositionAllocator> macroEnbPositionAlloc = CreateObject<ListPositionAllocator>();
    macroEnbPositionAlloc->Add(Vector(0.0, 0.0, hBS));
    if (numMacroGnb > 1) macroEnbPositionAlloc->Add(Vector(0.0, 80.0, hBS));
    MobilityHelper macroEnbmobility; macroEnbmobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    macroEnbmobility.SetPositionAllocator(macroEnbPositionAlloc); macroEnbmobility.Install(macroGnbNodes);
    // FAP Mobility (Fixed)
    Ptr<ListPositionAllocator> fapPositionAlloc = CreateObject<ListPositionAllocator>();
    fapPositionAlloc->Add(Vector(40.0, 5.0, hFAP));  // FAP 0 Pos
    if (numFaps > 1) fapPositionAlloc->Add(Vector(35.0, 45.0, hFAP)); // FAP 1 Pos
    MobilityHelper fapmobility; fapmobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    fapmobility.SetPositionAllocator(fapPositionAlloc); fapmobility.Install(fapNodes);
    // UE Mobility (Set static positions for all)
    MobilityHelper uemobility; uemobility.SetMobilityModel("ns3::ConstantPositionMobilityModel"); uemobility.Install(vehicles);
    // Assign static positions relevant to attack plan
    // Legit near FAP 0
    if (numUes >= 1) vehicles.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(42, 3, hUT));
    // Legit near FAP 1
    if (numUes >= 2) vehicles.Get(1)->GetObject<MobilityModel>()->SetPosition(Vector(37, 42, hUT));
     // Legit near Macro 0
    if (numUes >= 3) vehicles.Get(2)->GetObject<MobilityModel>()->SetPosition(Vector(5, 5, hUT));
    // Attacker near FAP 0
    if (numUes >= 4) vehicles.Get(3)->GetObject<MobilityModel>()->SetPosition(Vector(38, 7, hUT));
    // Attacker near FAP 1
    if (numUes >= 5) vehicles.Get(4)->GetObject<MobilityModel>()->SetPosition(Vector(33, 47, hUT));
     // Legit near Macro 1
    if (numUes >= 6) vehicles.Get(5)->GetObject<MobilityModel>()->SetPosition(Vector(5, 75, hUT));
    // Legit near Macro 1
    if (numUes >= 7) vehicles.Get(6)->GetObject<MobilityModel>()->SetPosition(Vector(10, 85, hUT));


    // --- NR Setup ---
    Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();
    nrHelper->SetBeamformingHelper(idealBeamformingHelper);
    nrHelper->SetEpcHelper(epcHelper);
    // BWP Config
    BandwidthPartInfoPtrVector allBwps; CcBwpCreator ccBwpCreator; const uint8_t numCcPerBand = 1;
    CcBwpCreator::SimpleOperationBandConf bandConf(frequency, bandwidth, numCcPerBand, scenario);
    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);
    nrHelper->InitializeOperationBand(&band); allBwps = CcBwpCreator::GetAllBwps({band});
    // Beamforming, Scheduler, Antennas
    idealBeamformingHelper->SetAttribute("BeamformingMethod", TypeIdValue(DirectPathBeamforming::GetTypeId()));
    nrHelper->SetSchedulerTypeId(NrMacSchedulerTdmaRR::GetTypeId());
    nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(2)); nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(4));
    nrHelper->SetUeAntennaAttribute("AntennaElement", PointerValue(CreateObject<IsotropicAntennaModel>()));
    nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(8)); nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    nrHelper->SetGnbAntennaAttribute("AntennaElement", PointerValue(CreateObject<IsotropicAntennaModel>()));
    // Install NR Devices
    std::cout << "Installing NR Devices on UEs, Macro gNBs, and FAPs..." << std::endl;
    NetDeviceContainer ueNetDevices = nrHelper->InstallUeDevice(vehicles, allBwps);
    NetDeviceContainer macroGnbNetDevices = nrHelper->InstallGnbDevice(macroGnbNodes, allBwps);
    NetDeviceContainer fapNetDevices = nrHelper->InstallGnbDevice(fapNodes, allBwps);
    // Set Tx Power
    std::cout << "Setting Tx Power..." << std::endl;
    for (uint32_t i = 0; i < macroGnbNetDevices.GetN(); ++i) { /* set macro power */ Ptr<NrGnbNetDevice> gnbDev=DynamicCast<NrGnbNetDevice>(macroGnbNetDevices.Get(i)); if(gnbDev&&gnbDev->GetPhy(0)) gnbDev->GetPhy(0)->SetTxPower(txPowerMacro); }
    for (uint32_t i = 0; i < fapNetDevices.GetN(); ++i) { /* set fap power */ Ptr<NrGnbNetDevice> gnbDev=DynamicCast<NrGnbNetDevice>(fapNetDevices.Get(i)); if(gnbDev&&gnbDev->GetPhy(0)) gnbDev->GetPhy(0)->SetTxPower(txPowerFAP); }
    for (uint32_t i = 0; i < ueNetDevices.GetN(); ++i) { /* set ue power */ Ptr<NrUeNetDevice> ueDev=DynamicCast<NrUeNetDevice>(ueNetDevices.Get(i)); if(ueDev&&ueDev->GetPhy(0)) ueDev->GetPhy(0)->SetTxPower(ueTxPower); }
    // Assign Streams
    int64_t randomStream = 1; randomStream += nrHelper->AssignStreams(macroGnbNetDevices, randomStream);
    randomStream += nrHelper->AssignStreams(fapNetDevices, randomStream); randomStream += nrHelper->AssignStreams(ueNetDevices, randomStream);
    // Update Config
    std::cout << "Updating NR device configurations..." << std::endl;
    for(auto it=macroGnbNetDevices.Begin(); it!=macroGnbNetDevices.End(); ++it) DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for(auto it=fapNetDevices.Begin(); it!=fapNetDevices.End(); ++it) DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for(auto it=ueNetDevices.Begin(); it!=ueNetDevices.End(); ++it) DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();

    // Build Cell ID Map
    std::map<uint16_t, Ptr<Node>> cellIdToNodeMap; std::cout << "Building Cell ID to Node map..." << std::endl;
    for(uint32_t i=0; i<macroGnbNetDevices.GetN(); ++i) { Ptr<NrGnbNetDevice> gnbDev=DynamicCast<NrGnbNetDevice>(macroGnbNetDevices.Get(i)); if(gnbDev) cellIdToNodeMap[gnbDev->GetCellId()]=macroGnbNodes.Get(i); }
    for(uint32_t i=0; i<fapNetDevices.GetN(); ++i) { Ptr<NrGnbNetDevice> fapDev=DynamicCast<NrGnbNetDevice>(fapNetDevices.Get(i)); if(fapDev) cellIdToNodeMap[fapDev->GetCellId()]=fapNodes.Get(i); }

    // --- Internet & Core Network ---
    Ptr<Node> pgw=epcHelper->GetPgwNode(); NodeContainer remoteHostContainer; remoteHostContainer.Create(1); Ptr<Node> remoteHost=remoteHostContainer.Get(0);
    InternetStackHelper internet; internet.Install(remoteHostContainer);
    PointToPointHelper p2ph; p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s"))); p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500)); p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.010)));
    NetDeviceContainer internetDevices=p2ph.Install(pgw, remoteHost);
    Ipv4AddressHelper ipv4h; ipv4h.SetBase("1.0.0.0", "255.0.0.0"); Ipv4InterfaceContainer internetIpIfaces=ipv4h.Assign(internetDevices); Ipv4Address remoteHostAddr=internetIpIfaces.GetAddress(1);
    Ipv4StaticRoutingHelper ipv4RoutingHelper; Ptr<Ipv4StaticRouting> remoteHostStaticRouting=ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>()); remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);
    internet.Install(vehicles); internet.Install(macroGnbNodes); internet.Install(fapNodes);
    Ptr<ListPositionAllocator> fixedAlloc=CreateObject<ListPositionAllocator>(); fixedAlloc->Add(Vector(100.0, 100.0, 0)); fixedAlloc->Add(Vector(120.0, 100.0, 0));
    MobilityHelper fixedMobility; fixedMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel"); fixedMobility.SetPositionAllocator(fixedAlloc); fixedMobility.Install(NodeContainer(pgw, remoteHost));

    // Assign UE IPs
    Ipv4InterfaceContainer ueIpIface = epcHelper->AssignUeIpv4Address(NetDeviceContainer(ueNetDevices));

    // Attach UEs
    NetDeviceContainer allGnbNetDevices; allGnbNetDevices.Add(macroGnbNetDevices); allGnbNetDevices.Add(fapNetDevices);
    std::cout << "Attaching UEs to the closest gNB (Macro or FAP)..." << std::endl;
    nrHelper->AttachToClosestGnb(ueNetDevices, allGnbNetDevices);

    // UE Default Routes
    for(uint32_t u=0; u<vehicles.GetN(); ++u) { Ptr<Ipv4StaticRouting> ueStaticRouting=ipv4RoutingHelper.GetStaticRouting(vehicles.Get(u)->GetObject<Ipv4>()); ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1); }


    // --- Legitimate Downlink Applications ---
    std::cout << "Setting up Legitimate Downlink Traffic (RemoteHost -> UEs on port " << dlPort << ")" << std::endl;
    ApplicationContainer downlinkServers, downlinkClients;
    // Servers on all UEs
    for(uint16_t i=0; i<vehicles.GetN(); ++i) { UdpServerHelper dlServerHelper(dlPort); ApplicationContainer serverApp=dlServerHelper.Install(vehicles.Get(i)); serverApp.Start(Seconds(0.0)); serverApp.Stop(simStopTime); downlinkServers.Add(serverApp); }
    // Clients send only to legitimate UEs
    std::vector<uint16_t> allLegitUeIndices = fapLegitUeIndices;
    allLegitUeIndices.insert(allLegitUeIndices.end(), macroLegitUeIndices.begin(), macroLegitUeIndices.end());
    for(uint16_t i : allLegitUeIndices) { UdpClientHelper dlClientHelper(ueIpIface.GetAddress(i), dlPort); dlClientHelper.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF)); dlClientHelper.SetAttribute("Interval", TimeValue(MilliSeconds(100))); dlClientHelper.SetAttribute("PacketSize", UintegerValue(1024)); ApplicationContainer clientApp=dlClientHelper.Install(remoteHost); clientApp.Start(Seconds(1.0)); clientApp.Stop(simStopTime - Seconds(1.0)); downlinkClients.Add(clientApp); }


    // --- Uplink Applications (Legitimate AND DDoS Attack Traffic) ---
    std::cout << "Setting up Uplink Traffic..." << std::endl;
    // Legitimate UL Server on Remote Host (Also target for attack traffic)
    UdpServerHelper ulServerHelper(ulPort);
    ApplicationContainer ulServerApp = ulServerHelper.Install(remoteHost);
    ulServerApp.Start(Seconds(0.0));
    ulServerApp.Stop(simStopTime);

    ApplicationContainer uplinkClients;

    for (uint16_t i = 0; i < vehicles.GetN(); ++i)
    {
        if (IsIndexInList(i, attackerUeIndices)) // This is an Attacker UE
        {
            // --- Configure Attacker Client (Flooding Uplink Radio via RemoteHost target) ---
            std::cout << "  Configuring Attacker UE " << i << " to flood RemoteHost " << remoteHostAddr << ":" << ulPort << std::endl;

            UdpClientHelper attackerClientHelper(remoteHostAddr, ulPort); // Target Remote Host Server
            attackerClientHelper.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF)); // Send until stopped by time
            attackerClientHelper.SetAttribute("Interval", TimeValue(attackerInterval)); // High rate
            attackerClientHelper.SetAttribute("PacketSize", UintegerValue(attackerPacketSize));
            ApplicationContainer attackerApp = attackerClientHelper.Install(vehicles.Get(i)); // Install on attacker
            attackerApp.Start(ddosStartTime); // Start attack
            attackerApp.Stop(ddosStopTime);   // Stop attack
            uplinkClients.Add(attackerApp);

        } else { // This is a Legitimate UE (FAP-assoc or Macro-assoc)
            // --- Configure Legitimate Uplink Client ---
            std::cout << "  Configuring Legitimate Uplink Client on UE " << i << " to " << remoteHostAddr << ":" << ulPort << std::endl;
            UdpClientHelper ulClientHelper(remoteHostAddr, ulPort); // Target Remote Host
            ulClientHelper.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
            ulClientHelper.SetAttribute("Interval", TimeValue(MilliSeconds(120))); // Normal rate
            ulClientHelper.SetAttribute("PacketSize", UintegerValue(512));
            ApplicationContainer ulClientApp = ulClientHelper.Install(vehicles.Get(i)); // Install on legitimate UE
            ulClientApp.Start(Seconds(1.5)); // Normal start
            ulClientApp.Stop(simStopTime - Seconds(1.0)); // Normal stop
            uplinkClients.Add(ulClientApp);
        }
    }


    // --- Visualization (NetAnim) (Modified for Attackers/Impacted Legit) ---
    AnimationInterface anim("scenario-vanet-nr-fap-flood.xml"); // New filename
    anim.EnablePacketMetadata(true);

    // Node Colors and Descriptions
    for(uint32_t i=0; i<macroGnbNodes.GetN(); ++i) anim.UpdateNodeColor(macroGnbNodes.Get(i), 255, 0, 0); // Red Macro
    for(uint32_t i=0; i<fapNodes.GetN(); ++i) anim.UpdateNodeColor(fapNodes.Get(i), 255, 0, 255);       // Magenta FAP
    anim.UpdateNodeColor(pgw, 128, 128, 128);         // Gray PGW
    anim.UpdateNodeColor(remoteHost, 0, 255, 0);      // Green RemoteHost

    for (uint32_t i = 0; i < vehicles.GetN(); ++i) { // Color UEs based on role
         if (IsIndexInList(i, attackerUeIndices)) {
             anim.UpdateNodeColor(vehicles.Get(i), 255, 165, 0); // Orange Attacker
             anim.UpdateNodeDescription(vehicles.Get(i), "ATTACKER-" + std::to_string(i));
         } else if (IsIndexInList(i, fapLegitUeIndices)) {
             anim.UpdateNodeColor(vehicles.Get(i), 0, 191, 255); // DeepSkyBlue FAP-Legit (Victim of circumstance)
             anim.UpdateNodeDescription(vehicles.Get(i), "FAP-LEGIT-" + std::to_string(i));
         } else { // macroLegitUeIndices
             anim.UpdateNodeColor(vehicles.Get(i), 0, 0, 255);   // Blue Macro-Legit
             anim.UpdateNodeDescription(vehicles.Get(i), "MACRO-LEGIT-" + std::to_string(i));
         }
    }

    if(macroGnbNodes.GetN()>0) anim.UpdateNodeDescription(macroGnbNodes.Get(0), "Macro-gNB-1");
    if(macroGnbNodes.GetN()>1) anim.UpdateNodeDescription(macroGnbNodes.Get(1), "Macro-gNB-2");
    for(uint32_t i=0; i<fapNodes.GetN(); ++i) { anim.UpdateNodeDescription(fapNodes.Get(i), "FAP-" + std::to_string(i+1)); }
    anim.UpdateNodeDescription(pgw, "PGW"); anim.UpdateNodeDescription(remoteHost, "RemoteHost");


    // --- Simulation Execution & Analysis ---
    Ptr<FlowMonitor> flowMonitor; FlowMonitorHelper flowHelper; flowMonitor = flowHelper.InstallAll();

    std::cout << "\n--- Running Simulation (Duration: " << simStopTime.GetSeconds() << "s) ---" << std::endl;
    std::cout << "--- FAP Uplink Radio Flood Attack Period: " << ddosStartTime.GetSeconds() << "s to " << ddosStopTime.GetSeconds() << "s ---" << std::endl;
    std::cout << "--- Attackers (Flooding Uplink): UEs "; for(auto idx:attackerUeIndices) std::cout << idx << " "; std::cout << "---\n";
    std::cout << "--- Legitimate UEs Near FAPs (Observe Impact): UEs "; for(auto idx:fapLegitUeIndices) std::cout << idx << " "; std::cout << "---\n";

    Simulator::Stop(simStopTime);
    Simulator::Run(); // <<< Simulation runs here
    std::cout << "--- Simulation Finished ---" << std::endl;


    // --- Output Results ---
    // UE IPs
    std::cout << "\n--- Vehicle (UE) IP Addresses ---\n";
     for (uint32_t i = 0; i < vehicles.GetN(); i++) {
        Ptr<Ipv4> ipv4 = vehicles.Get(i)->GetObject<Ipv4>();
        std::string role = "Macro-Legit";
        if(IsIndexInList(i, attackerUeIndices)) role = "Attacker";
        else if (IsIndexInList(i, fapLegitUeIndices)) role = "FAP-Legit";
        if (ipv4->GetNInterfaces() > 1) { Ipv4Address ipAddr = ipv4->GetAddress(1, 0).GetLocal(); std::cout << "UE " << i << " (" << role << ") IP: " << ipAddr << std::endl;
        } else { std::cout << "UE " << i << " (" << role << ") IP: Not found" << std::endl; }
    }
    // Remote Host IP
     std::cout << "\n----------- Remote Host IP Address --------------\n";
    Ptr<Ipv4> rh_ipv4 = remoteHost->GetObject<Ipv4>();
    if (rh_ipv4->GetNInterfaces() > 1) { Ipv4Address rh_ipAddr = rh_ipv4->GetAddress(1, 0).GetLocal(); std::cout << "Remotehost IP: " << rh_ipAddr << std::endl;
    } else { std::cout << "Remotehost IP: Not found" << std::endl; }

    // Flow Monitor Analysis
    flowMonitor->CheckForLostPackets(); Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();
    std::cout << "\n----------- Flow Monitor Statistics ----------- \n";
     for (auto const& [flowId, flowStats] : stats) { /* Flow Analysis Loop */
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flowId);
        std::string flowDesc = "Unknown"; bool isAttackFlow = false; bool isImpactedLegitUl = false; bool isOtherLegitUl = false;

        // Classify flow
        bool srcIsAttacker = IsAddressInList(t.sourceAddress, ueIpIface, attackerUeIndices, vehicles);
        bool srcIsFapLegit = IsAddressInList(t.sourceAddress, ueIpIface, fapLegitUeIndices, vehicles);
        bool srcIsMacroLegit = IsAddressInList(t.sourceAddress, ueIpIface, macroLegitUeIndices, vehicles);

        if (t.destinationAddress == remoteHostAddr && t.destinationPort == ulPort) { // Uplink
            if (srcIsAttacker) { flowDesc = "Attacker UL Flood"; isAttackFlow = true; }
            else if (srcIsFapLegit) { flowDesc = "FAP-Legit UL"; isImpactedLegitUl = true; }
            else if (srcIsMacroLegit) { flowDesc = "Macro-Legit UL"; isOtherLegitUl = true; }
            else { flowDesc = "Other UL"; }
        } else if (t.sourceAddress == remoteHostAddr && t.destinationPort == dlPort) { // Downlink
             if (IsAddressInList(t.destinationAddress, ueIpIface, fapLegitUeIndices, vehicles)) { flowDesc = "FAP-Legit DL"; }
             else if (IsAddressInList(t.destinationAddress, ueIpIface, macroLegitUeIndices, vehicles)) { flowDesc = "Macro-Legit DL"; }
             else { flowDesc = "Other DL"; }
        }

        std::cout << "Flow ID: " << flowId << " (" << flowDesc << ")";
        std::cout << " Src: " << t.sourceAddress << ":" << t.sourcePort << " Dst: " << t.destinationAddress << ":" << t.destinationPort << std::endl;
        // Print basic stats
        std::cout << "  Tx Packets: " << flowStats.txPackets << " (" << flowStats.txBytes << " bytes)" << std::endl;
        std::cout << "  Rx Packets: " << flowStats.rxPackets << " (" << flowStats.rxBytes << " bytes)" << std::endl;
        std::cout << "  Lost Packets: " << flowStats.lostPackets << std::endl;
        if (flowStats.txPackets > 0) { double lossRatio = (double)flowStats.lostPackets / flowStats.txPackets; std::cout << "  Loss Ratio: " << std::fixed << std::setprecision(4) << lossRatio << std::endl; }
        if (flowStats.rxPackets > 0) { /* Print Delay/Throughput/Jitter */
            Time delaySum = flowStats.delaySum; Time duration = flowStats.timeLastRxPacket - flowStats.timeFirstTxPacket;
            std::cout << "  Mean Delay: " << (delaySum / flowStats.rxPackets).GetSeconds() << " s" << std::endl;
            if (duration > Time(0)) { std::cout << "  Throughput: " << (flowStats.rxBytes * 8.0 / duration.GetSeconds() / 1024) << " Kbps" << std::endl; }
            else { std::cout << "  Throughput: N/A (duration=0)" << std::endl; }
            if (flowStats.rxPackets > 1) { std::cout << "  Mean Jitter: " << (flowStats.jitterSum / (flowStats.rxPackets - 1)).GetSeconds() << " s" << std::endl; }
            else { std::cout << "  Mean Jitter: N/A (<= 1 Rx packet)" << std::endl; }
        } else { std::cout << "  No Packets Received" << std::endl; }
        std::cout << "------------------------------------------" << std::endl;
    }


    // Connectivity Check (Using custom GetCellId)
    std::cout << "\n--- UE Connectivity Status (End of Simulation) ---\n";
     for (uint32_t i = 0; i < vehicles.GetN(); ++i) { /* Connectivity Check Loop */
        Ptr<NetDevice> ueDev = vehicles.Get(i)->GetDevice(0); Ptr<NrUeNetDevice> nrUeDev = DynamicCast<NrUeNetDevice>(ueDev);
        std::cout << "UE " << i << " (Node ID: " << vehicles.Get(i)->GetId() << "): ";
        if (nrUeDev) { uint16_t servingCellId = nrUeDev->GetCellId(); /* Using custom function */
            if (servingCellId != UINT16_MAX) { auto it = cellIdToNodeMap.find(servingCellId);
                 if (it != cellIdToNodeMap.end()) { Ptr<Node> servingNode = it->second; bool isMacro = false;
                     for(uint32_t j=0; j < macroGnbNodes.GetN(); ++j) { if (macroGnbNodes.Get(j) == servingNode) { isMacro = true; break; } }
                     std::cout << "Connected to Cell ID " << servingCellId << " (Node ID: " << servingNode->GetId() << ", Type: " << (isMacro ? "Macro gNB" : "FAP") << ")" << std::endl;
                 } else { std::cout << "Connected to Cell ID " << servingCellId << " (Node mapping not found!)" << std::endl; }
            } else { std::cout << "Not connected (Reported Cell ID: 0x" << std::hex << servingCellId << std::dec << ")" << std::endl; }
        } else { std::cout << "NR UE Device not found!" << std::endl; }
    }


    Simulator::Destroy();
    std::cout << "--- Simulation Destroyed ---" << std::endl;
    return 0;
}
