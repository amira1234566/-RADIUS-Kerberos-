#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/spectrum-module.h"
#include "ns3/propagation-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mac16-address.h"

#include <iostream>
#include <string>

using namespace ns3;

static const uint16_t RADIUS_PORT = 1812;
static const uint16_t KDC_PORT    = 8888;
static const uint16_t TELE_PORT   = 61616;

// =============== Kerberos-like Ticket Header (4 bytes) ===============
class TicketHeader : public Header
{
public:
  TicketHeader() : m_magic(0) {}
  explicit TicketHeader(uint32_t magic) : m_magic(magic) {}

  static TypeId GetTypeId()
  {
    static TypeId tid = TypeId("TicketHeader")
      .SetParent<Header>()
      .AddConstructor<TicketHeader>();
    return tid;
  }

  TypeId GetInstanceTypeId() const override { return GetTypeId(); }

  uint32_t GetSerializedSize() const override { return 4; }

  void Serialize(Buffer::Iterator start) const override
  {
    start.WriteHtonU32(m_magic);
  }

  uint32_t Deserialize(Buffer::Iterator start) override
  {
    m_magic = start.ReadNtohU32();
    return 4;
  }

  void Print(std::ostream &os) const override
  {
    os << "magic=0x" << std::hex << m_magic << std::dec;
  }

  uint32_t GetMagic() const { return m_magic; }

private:
  uint32_t m_magic;
};

// =============== Gateway Telemetry Server (ticket verification) ===============
class SecureTelemetryServerApp : public Application
{
public:
  void Setup(uint16_t port, bool requireTicket, uint32_t ticketMagic)
  {
    m_port = port;
    m_requireTicket = requireTicket;
    m_ticketMagic = ticketMagic;
  }

  uint64_t GetAccepted() const { return m_accepted; }
  uint64_t GetDropped() const  { return m_dropped; }

private:
  void StartApplication() override
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    Inet6SocketAddress local = Inet6SocketAddress(Ipv6Address::GetAny(), m_port);
    m_socket->Bind(local);
    m_socket->SetRecvCallback(MakeCallback(&SecureTelemetryServerApp::HandleRead, this));
  }

  void StopApplication() override
  {
    if (m_socket)
    {
      m_socket->Close();
      m_socket = nullptr;
    }
  }

  void HandleRead(Ptr<Socket> socket)
  {
    Address from;
    Ptr<Packet> p = socket->RecvFrom(from);
    if (!p) return;

    if (!m_requireTicket)
    {
      m_accepted++;
      return;
    }

    TicketHeader th;
    if (p->PeekHeader(th) == 0)
    {
      m_dropped++;
      return;
    }

    // verify
    if (th.GetMagic() == m_ticketMagic)
      m_accepted++;
    else
      m_dropped++;
  }

  Ptr<Socket> m_socket;
  uint16_t m_port = 0;
  bool m_requireTicket = false;
  uint32_t m_ticketMagic = 0;

  uint64_t m_accepted = 0;
  uint64_t m_dropped = 0;
};

// =============== Sender App (sensor or attacker) ===============
class SecureSenderApp : public Application
{
public:
  void Setup(Ipv6Address dst, uint16_t port, Time interval, uint32_t pktSize,
             bool includeTicket, uint32_t ticketMagic)
  {
    m_dst = dst;
    m_port = port;
    m_interval = interval;
    m_pktSize = pktSize;
    m_includeTicket = includeTicket;
    m_ticketMagic = ticketMagic;
  }

private:
  void StartApplication() override
  {
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sendEvent = Simulator::Schedule(Seconds(0.0), &SecureSenderApp::Send, this);
  }

  void StopApplication() override
  {
    if (m_sendEvent.IsRunning())
      Simulator::Cancel(m_sendEvent);

    if (m_socket)
    {
      m_socket->Close();
      m_socket = nullptr;
    }
  }

  void Send()
  {
    Ptr<Packet> p = Create<Packet>(m_pktSize);

    if (m_includeTicket)
    {
      TicketHeader th(m_ticketMagic);
      p->AddHeader(th);
    }

    Inet6SocketAddress remote = Inet6SocketAddress(m_dst, m_port);
    m_socket->SendTo(p, 0, remote);

    m_sendEvent = Simulator::Schedule(m_interval, &SecureSenderApp::Send, this);
  }

  Ptr<Socket> m_socket;
  EventId m_sendEvent;

  Ipv6Address m_dst;
  uint16_t m_port = 0;
  Time m_interval = Seconds(1.0);
  uint32_t m_pktSize = 64;

  bool m_includeTicket = false;
  uint32_t m_ticketMagic = 0;
};

int main(int argc, char *argv[])
{
  // ---------- Parameters ----------
  uint32_t nSensors = 10;
  double simTime = 20.0;

  bool enableAttack = false;
  uint32_t nAttackers = 2;

  bool defense = false; // if true: gateway requires ticket for telemetry

  double sensorInterval = 0.5;
  uint32_t sensorPktSize = 64;

  double attackIntervalMs = 5.0;
  uint32_t attackPktSize = 256;

  CommandLine cmd;
  cmd.AddValue("nSensors", "Number of IoT sensors", nSensors);
  cmd.AddValue("simTime", "Simulation time (seconds)", simTime);
  cmd.AddValue("enableAttack", "Enable attackers", enableAttack);
  cmd.AddValue("nAttackers", "Number of attackers", nAttackers);
  cmd.AddValue("defense", "Enable Kerberos-like defense (ticket required)", defense);

  cmd.AddValue("sensorInterval", "Sensor telemetry interval (s)", sensorInterval);
  cmd.AddValue("sensorPktSize", "Sensor packet size (bytes)", sensorPktSize);

  cmd.AddValue("attackIntervalMs", "Attack interval (ms)", attackIntervalMs);
  cmd.AddValue("attackPktSize", "Attack packet size (bytes)", attackPktSize);

  cmd.Parse(argc, argv);

  // ---------- Nodes ----------
  NodeContainer sensors;
  sensors.Create(nSensors);

  Ptr<Node> gateway = CreateObject<Node>();
  Ptr<Node> kdc     = CreateObject<Node>();

  NodeContainer attackers;
  attackers.Create(enableAttack ? nAttackers : 0);

  NodeContainer all;
  all.Add(sensors);
  all.Add(gateway);
  all.Add(kdc);
  all.Add(attackers);

  uint32_t gwIndex  = nSensors;     // sensors: 0..nSensors-1, gateway: nSensors
  uint32_t kdcIndex = nSensors + 1; // kdc after gateway

  // ---------- Mobility ----------
  MobilityHelper mobility;
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(all);

  for (uint32_t i = 0; i < nSensors; ++i)
  {
    sensors.Get(i)->GetObject<MobilityModel>()->SetPosition(Vector(1.5 * i, 0.0, 0.0));
  }
  gateway->GetObject<MobilityModel>()->SetPosition(Vector(7.0, 5.0, 0.0));
  kdc->GetObject<MobilityModel>()->SetPosition(Vector(7.0, 8.0, 0.0));

  for (uint32_t i = 0; i < attackers.GetN(); ++i)
  {
    attackers.Get(i)->GetObject<MobilityModel>()->SetPosition(Vector(10.0 + 1.0 * i, 10.0, 0.0));
  }

  // ---------- LR-WPAN Channel (Spectrum) ----------
  Ptr<SingleModelSpectrumChannel> channel = CreateObject<SingleModelSpectrumChannel>();
  Ptr<LogDistancePropagationLossModel> loss = CreateObject<LogDistancePropagationLossModel>();
  Ptr<ConstantSpeedPropagationDelayModel> delay = CreateObject<ConstantSpeedPropagationDelayModel>();
  channel->AddPropagationLossModel(loss);
  channel->SetPropagationDelayModel(delay);

  // ---------- LR-WPAN Devices ----------
  LrWpanHelper lrWpanHelper;
  lrWpanHelper.SetChannel(channel);

  NetDeviceContainer lrwpanDevs = lrWpanHelper.Install(all);

  // IMPORTANT: Unique PAN ID + ShortAddress to avoid IPv6 address collision
  const uint16_t panId = 0x1234;
  for (uint32_t i = 0; i < lrwpanDevs.GetN(); ++i)
  {
    Ptr<LrWpanNetDevice> dev = DynamicCast<LrWpanNetDevice>(lrwpanDevs.Get(i));
    if (dev)
    {
      dev->GetMac()->SetPanId(panId);
      dev->GetMac()->SetShortAddress(Mac16Address(i + 1)); // unique
    }
  }

  // ---------- 6LoWPAN ----------
  SixLowPanHelper sixlowpan;
  NetDeviceContainer sixDevs = sixlowpan.Install(lrwpanDevs);

  // ---------- IPv6 Stack ----------
  InternetStackHelper internet;
  internet.Install(all);

  Ipv6AddressHelper ipv6;
  ipv6.SetBase(Ipv6Address("2001:db8:1::"), Ipv6Prefix(64));
  Ipv6InterfaceContainer ifs = ipv6.Assign(sixDevs);

  ifs.SetForwarding(gwIndex, true);
  ifs.SetDefaultRouteInAllNodes(gwIndex);

  std::cout << "---- IPv6 global addresses (index 1) ----" << std::endl;
  for (uint32_t i = 0; i < ifs.GetN(); ++i)
  {
    std::cout << "Node " << i << " IPv6: " << ifs.GetAddress(i, 1) << std::endl;
  }

  Ipv6Address gwAddr  = ifs.GetAddress(gwIndex, 1);
  Ipv6Address kdcAddr = ifs.GetAddress(kdcIndex, 1);

  // ---------- KDC + RADIUS Servers (counts only, proof for report) ----------
  UdpServerHelper kdcServer(KDC_PORT);
  ApplicationContainer kdcSrvApp = kdcServer.Install(kdc);
  kdcSrvApp.Start(Seconds(0.5));
  kdcSrvApp.Stop(Seconds(simTime));

  UdpServerHelper radiusServer(RADIUS_PORT);
  ApplicationContainer radiusSrvApp = radiusServer.Install(gateway);
  radiusSrvApp.Start(Seconds(0.5));
  radiusSrvApp.Stop(Seconds(simTime));

  // ---------- RADIUS-like Access-Request ----------
  for (uint32_t i = 0; i < nSensors; ++i)
  {
    UdpClientHelper accessReq(gwAddr, RADIUS_PORT);
    accessReq.SetAttribute("MaxPackets", UintegerValue(1));
    accessReq.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    accessReq.SetAttribute("PacketSize", UintegerValue(32));

    ApplicationContainer a = accessReq.Install(sensors.Get(i));
    a.Start(Seconds(1.0 + 0.01 * i));
    a.Stop(Seconds(simTime));
  }

  // ---------- Kerberos-like Ticket-Request to KDC ----------
  // spaced to reduce collision on 802.15.4
  for (uint32_t i = 0; i < nSensors; ++i)
  {
    UdpClientHelper ticketReq(kdcAddr, KDC_PORT);
    ticketReq.SetAttribute("MaxPackets", UintegerValue(1));
    ticketReq.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    ticketReq.SetAttribute("PacketSize", UintegerValue(40));

    ApplicationContainer t = ticketReq.Install(sensors.Get(i));
    t.Start(Seconds(1.2 + 0.2 * i));
    t.Stop(Seconds(simTime));
  }

  // ---------- Secure Telemetry ----------
  const uint32_t ticketMagic = 0xAABBCCDD;
  bool requireTicket = defense;

  Ptr<SecureTelemetryServerApp> teleSrv = CreateObject<SecureTelemetryServerApp>();
  teleSrv->Setup(TELE_PORT, requireTicket, ticketMagic);
  gateway->AddApplication(teleSrv);
  teleSrv->SetStartTime(Seconds(1.0));
  teleSrv->SetStopTime(Seconds(simTime));

  // Sensors send telemetry WITH ticket
  for (uint32_t i = 0; i < nSensors; ++i)
  {
    Ptr<SecureSenderApp> sApp = CreateObject<SecureSenderApp>();
    sApp->Setup(gwAddr, TELE_PORT, Seconds(sensorInterval), sensorPktSize, true, ticketMagic);
    sensors.Get(i)->AddApplication(sApp);
    sApp->SetStartTime(Seconds(2.0 + 0.05 * i));
    sApp->SetStopTime(Seconds(simTime));
  }

  // Attackers send telemetry WITHOUT ticket (dropped when defense=1)
  if (attackers.GetN() > 0)
  {
    for (uint32_t i = 0; i < attackers.GetN(); ++i)
    {
      Ptr<SecureSenderApp> aApp = CreateObject<SecureSenderApp>();
      aApp->Setup(gwAddr, TELE_PORT, MilliSeconds(attackIntervalMs), attackPktSize, false, ticketMagic);
      attackers.Get(i)->AddApplication(aApp);
      aApp->SetStartTime(Seconds(2.0));
      aApp->SetStopTime(Seconds(simTime));
    }
  }

  // ---------- FlowMonitor ----------
  FlowMonitorHelper flowmonHelper;
  Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

  std::cout << "Running IoT scenario (ns-3.41): "
            << "sensors=" << nSensors
            << ", enableAttack=" << enableAttack
            << ", attackers=" << attackers.GetN()
            << ", defense=" << defense
            << ", simTime=" << simTime << "s"
            << std::endl;

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();

  // ---------- Post-Run prints ----------
  std::cout << "Gateway Telemetry accepted: " << teleSrv->GetAccepted() << std::endl;
  std::cout << "Gateway Telemetry dropped (invalid/no ticket): " << teleSrv->GetDropped() << std::endl;

  Ptr<UdpServer> rSrv = DynamicCast<UdpServer>(radiusSrvApp.Get(0));
  if (rSrv)
  {
    std::cout << "Gateway RADIUS-like received Access-Requests: " << rSrv->GetReceived() << std::endl;
  }

  Ptr<UdpServer> kSrv = DynamicCast<UdpServer>(kdcSrvApp.Get(0));
  if (kSrv)
  {
    std::cout << "KDC received Ticket-Requests: " << kSrv->GetReceived() << std::endl;
  }

  monitor->CheckForLostPackets();
  monitor->SerializeToXmlFile(defense ? "flowmon-iot-defense.xml"
                                      : (enableAttack ? "flowmon-iot-stress.xml"
                                                      : "flowmon-iot-baseline.xml"),
                              true, true);

  Simulator::Destroy();
  return 0;
}
