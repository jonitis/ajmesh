/******************************************************************************
 *    AllJoyn mesh test application
 ******************************************************************************/

#include <cstdio>

#include <array>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <qcc/StringUtil.h>
#include <qcc/Util.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/Init.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/Status.h>
#include <alljoyn/version.h>


using namespace ajn;
using namespace std;


static const char APPLICATION_NAME[] =                  "ajmesh";

static constexpr char CLUSTER_NODE_SERVICE_NAME[] =     "net.jonitis.AJMesh.Node";
static constexpr char CLUSTER_NODE_OBJECT_PATH[] =      "/net/jonitis/AJMesh";
static constexpr char CLUSTER_NODE_INTERFACE_NAME[] =   "net.jonitis.AJMesh.ClusterNode";

static constexpr char DEVICE_NAME_PREFIX[] = "dev_";
static constexpr SessionPort SERVICE_PORT = 25;
static constexpr uint32_t METHOD_CALL_TIMEOUT = 5000;


bool g_SecureInterface = false;
const char* g_AuthMechanism = nullptr;

#ifndef _WIN32
namespace std {
/** Method for creating non sharable objects, until this method is added to
 * C++14. */
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}
} /* namespace std */
#endif



class ClusterNodeObject;
class PeerNode;
class ProviderApplication;


class AllJoynInitializer {
public:
    AllJoynInitializer();
    ~AllJoynInitializer();
};


class AjRuntimeError : public std::runtime_error {
public:
    AjRuntimeError(QStatus status, const std::string& message) noexcept;
    ~AjRuntimeError() noexcept { }
    QStatus Status() const noexcept { return status; }

private:
    QStatus status;
};


class Application : private AuthListener, private SessionPortListener {
public:
    Application(const string& appName, const string& serviceName);
    Application(const Application& other) = delete;
    ~Application();
    Application& operator =(const Application& other) = delete;
    const BusAttachment& Bus() const { return bus; }
    BusAttachment& Bus() { return bus; }
    void FindAdvertisedName(const string& name);
    void RequestName();
    void AdvertiseName();

protected:
    void PreBusConnectInit();
    void PostBusConnectInit();
    void ConnectToAllJoynRouter();

    // AuthListener
    bool RequestCredentials(const char* authMechanism, const char* authPeer, uint16_t authCount,
        const char* userId, uint16_t credMask, Credentials& creds) override;
    bool VerifyCredentials(const char* authMechanism, const char* peerName, const Credentials& credentials) override;
    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) override;
    void SecurityViolation(QStatus status, const Message& msg) override;

    // SessionPortListener
    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) override;
    void SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner) override;

    void StopMessageBus();

private:
    void StartMessageBus();
    void BindSessionPort();
    void EnablePeerSecurity();

    BusAttachment bus;
    string appName;
    string serviceName;
    SessionPort port;
    SessionOpts opts;
};


class UnifiBusObject : public BusObject {
public:
    UnifiBusObject(Application& app, const string& serviceName, const string& objectPath);
    UnifiBusObject(const UnifiBusObject& other) = delete;
    ~UnifiBusObject() override = 0;
    UnifiBusObject& operator =(const UnifiBusObject& other) = delete;
    Application& App() { return app; }
    BusAttachment& Bus() { return bus; }
    QStatus MethodReply(const Message& msg, const MsgArg* args = nullptr, size_t numArgs = 0);
    QStatus MethodReply(const Message& msg, const char* error, const char* errorMessage = nullptr);
    QStatus MethodReply(const Message& msg, QStatus status);
    const string& ServiceName() const { return serviceName; }
    const string& ObjectPath() const { return objectPath; }

protected:
    void RegisterBusObject();

private:
    void UnregisterBusObject();

protected:
    Application& app;
    BusAttachment& bus;

private:
    string serviceName;
    string objectPath;
};


class UnifiProxyBusObject : public ProxyBusObject {
public:
    UnifiProxyBusObject(Application& app, const string& serviceName, const string& objectPath, SessionId sessionId);
    UnifiProxyBusObject(const UnifiProxyBusObject& other) = delete;
    ~UnifiProxyBusObject() override = 0;
    UnifiProxyBusObject& operator =(const UnifiProxyBusObject& other) = delete;
    Application& App() { return app; }
    BusAttachment& Bus() { return bus; }
    const string& ServiceName() const { return serviceName; }
    const string& ObjectPath() const { return objectPath; }

protected:
    QStatus MethodCall(const char* ifaceName, const char* methodName, const MsgArg* args, size_t numArgs,
        Message& replyMsg, uint32_t timeout = DefaultCallTimeout, uint8_t flags = 0) const override;
    void GetProperty(const char* iface, const char* property, MsgArg& value, uint32_t timeout = DefaultCallTimeout) const;
    void SetProperty(const char* iface, const char* property, MsgArg& value, uint32_t timeout = DefaultCallTimeout) const;
    string GetStringProperty(const char* interfaceName, const char* propertyName) const;
    void SetStringProperty(const char* interfaceName, const char* propertyName, const string& value);
    uint8_t GetByteProperty(const char* interfaceName, const char* propertyName) const;
    void SetByteProperty(const char* interfaceName, const char* propertyName, uint8_t value);
    int GetIntProperty(const char* interfaceName, const char* propertyName) const;
    void SetIntProperty(const char* interfaceName, const char* propertyName, int value);
    bool GetBoolProperty(const char* interfaceName, const char* propertyName) const;
    void SetBoolProperty(const char* interfaceName, const char* propertyName, bool value);

    Application& app;
    BusAttachment& bus;

private:
    string serviceName;
    string objectPath;
};


class ClusterNodeObject : public UnifiBusObject {
public:
    using PeerCollection = map<string, unique_ptr<PeerNode>>;           // key = service name

    ClusterNodeObject(Application& app, const string& serviceName, const string& objectPath);
    ~ClusterNodeObject();
    void Init();
    const PeerCollection& Peers() { return peers; }
    void AddPeer(unique_ptr<PeerNode> peer);
    void RemovePeer(const string& peerServiceName);
    void RemovePeer(PeerNode& peer);
    PeerNode* GetPeer(const string& peerServiceName) const;
    bool HasPeer(const string& peerServiceName) const;

private:
    void TestHandler(const InterfaceDescription::Member* member, Message& msg);

    void AttachInterfaces();
    void RegisterHandlers();

    const InterfaceDescription* intf = nullptr;
    PeerCollection peers;                                   // key = service name
    mutable std::mutex mutexPeers;                          // protect access to peers
};


class ClusterNodeProxy : public UnifiProxyBusObject {
public:
    ClusterNodeProxy(Application& app, const string& serviceName, const string& objectPath, SessionId sessionId);
    ~ClusterNodeProxy() override;
    void Init();
    string Test(const string& input) const;

private:
//    void PeerListChangedHandler(const InterfaceDescription::Member *member, const char *srcPath, Message &message);

    void AttachInterfaces();
    void RegisterHandlers();
    void UnregisterHandlers();

    const InterfaceDescription* intf = nullptr;
};


class PeerNode {
public:
    PeerNode(Application& app, const string& peerServiceName, SessionId sessionId);
    void Init();
    const ClusterNodeProxy& Proxy() const { return proxy; }
    ClusterNodeProxy& Proxy() { return proxy; }
    const string& ServiceName() const { return proxy.ServiceName(); }
    string RemoteTest(const string& input) const { return proxy.Test(input); }

private:
    ClusterNodeProxy proxy;
};



static void SleepMsecs(unsigned msecs)
{
#ifdef _WIN32
    Sleep(msecs);
#else
    usleep(msecs * 1000);
#endif
}

static string GetUniqueMacAddress()
{
    string mac = (qcc::RandHexString(6, true).c_str());

    return mac;
}

static const thread::id g_mainThread = this_thread::get_id();

const char* ThreadInfo()
{
    static string s_threadInfo;
    stringstream ss;

    auto id = this_thread::get_id();
    string prefix = (id == g_mainThread) ? "MT-" : "WT-";

    ss << setfill('0') << setw(8) << hex << id;
    s_threadInfo = prefix + ss.str();

    return s_threadInfo.c_str();
}

void BusCreateClusterNodeInterfaces(BusAttachment& bus)
{
    if (bus.GetInterface(CLUSTER_NODE_INTERFACE_NAME))
        return;

    InterfaceDescription* intf = nullptr;
    InterfaceSecurityPolicy securityPolicy = (g_SecureInterface) ? AJ_IFC_SECURITY_REQUIRED : AJ_IFC_SECURITY_INHERIT;

    QStatus status = bus.CreateInterface(CLUSTER_NODE_INTERFACE_NAME, intf, securityPolicy);
    if (status != ER_OK)
        throw AjRuntimeError(status, string("Failed to create interface ") + CLUSTER_NODE_INTERFACE_NAME);

    intf->AddMethod("Test", "s", "s", "input,result", 0);
    intf->Activate();
}


AjRuntimeError::AjRuntimeError(QStatus status, const std::string& message) noexcept :
    runtime_error("AllJoyn: " + message + " (" + QCC_StatusText(status) + ")"),
    status(status)
{ }

AllJoynInitializer::AllJoynInitializer()
{
    QStatus status = AllJoynInit();
    if (status != ER_OK)
        throw AjRuntimeError(status, "Failed to initialize AllJoyn library");

#ifdef ROUTER
    status = AllJoynRouterInit();
    if (status != ER_OK)
        throw AjRuntimeError(status, "Failed to initialize AllJoyn bundled router");
#endif
}

AllJoynInitializer::~AllJoynInitializer()
{
    QStatus status;

#ifdef ROUTER
    AllJoynRouterShutdown();
    status = AllJoynRouterShutdown();
    if (status != ER_OK) {
        fprintf(stderr, "Failed to shut down AllJoyn bundled router\n");
    }
#endif

    status = AllJoynShutdown();
    if (status != ER_OK) {
        fprintf(stderr, "Failed to shut down AllJoyn library");
    }
}


UnifiBusObject::UnifiBusObject(Application& app, const string& serviceName, const string& objectPath) :
    BusObject(objectPath.c_str()), app(app), bus(app.Bus()),
    serviceName(serviceName), objectPath(objectPath)
{ }

UnifiBusObject::~UnifiBusObject()
{
    UnregisterBusObject();
}

QStatus UnifiBusObject::MethodReply(const Message& msg, const MsgArg* args, size_t numArgs)
{
    QStatus status = BusObject::MethodReply(msg, args, numArgs);

    if (status != ER_OK) {
        fprintf(stderr, "UnifiBusObject::MethodReply() failed: %s\n", QCC_StatusText(status));
    }

    return status;
}

QStatus UnifiBusObject::MethodReply(const Message& msg, const char* error, const char* errorMessage)
{
    QStatus status = BusObject::MethodReply(msg, error, errorMessage);

    if (status != ER_OK) {
        fprintf(stderr, "UnifiBusObject::MethodReply() with error message %s:%s failed: %s\n", error, errorMessage ? errorMessage : "", QCC_StatusText(status));
    }

    return status;
}

QStatus UnifiBusObject::MethodReply(const Message& msg, QStatus status)
{
    QStatus qs = BusObject::MethodReply(msg, status);

    if (status != ER_OK) {
        fprintf(stderr, "UnifiBusObject::MethodReply() with status %s failed: %s\n", QCC_StatusText(status), QCC_StatusText(qs));
    }

    return qs;
}

void UnifiBusObject::RegisterBusObject()
{
    QStatus status = bus.RegisterBusObject(*this);
    if (status != ER_OK)
        throw AjRuntimeError(status, "RegisterBusObject failed");

    fprintf(stderr, "RegisterBusObject %s succeeded\n", ObjectPath().c_str());
}

void UnifiBusObject::UnregisterBusObject()
{
    bus.UnregisterBusObject(*this);

    fprintf(stderr, "UnregisterBusObject %s succeeded\n", ObjectPath().c_str());
}


UnifiProxyBusObject::UnifiProxyBusObject(Application& app, const string& serviceName, const string& objectPath, SessionId sessionId) :
    ProxyBusObject(app.Bus(), serviceName.c_str(), objectPath.c_str(), sessionId),
    app(app), bus(app.Bus()), serviceName(serviceName), objectPath(objectPath)
{ }

UnifiProxyBusObject::~UnifiProxyBusObject()
{ }

QStatus UnifiProxyBusObject::MethodCall(const char* ifaceName, const char* methodName, const MsgArg* args, size_t numArgs,
    Message& replyMsg, uint32_t timeout, uint8_t flags) const
{
    QStatus status = ProxyBusObject::MethodCall(ifaceName, methodName, args, numArgs, replyMsg, timeout, flags);
    if (status != QStatus::ER_OK) {
        string error = string("MethodCall ") + ifaceName + "." + methodName + "() on " + ServiceName() + ObjectPath() + " failed";
        qcc::String errDescription = replyMsg->GetErrorDescription();

        if (!errDescription.empty()) {
            error += " (" + string(errDescription.c_str()) + ")";
        }

        throw AjRuntimeError(status, error);
    }

    return status;  // Always success
}

void UnifiProxyBusObject::GetProperty(const char* iface, const char* property, MsgArg& value, uint32_t timeout) const
{
    QStatus status = ProxyBusObject::GetProperty(iface, property, value, timeout);
    if (status != QStatus::ER_OK) {
        string error = string("Get property ") + iface + "." + property + " on " + ServiceName() + ObjectPath() + " failed";

        if (status == ER_BUS_REPLY_IS_ERROR_MESSAGE && value.typeId == ALLJOYN_STRING) {
            const char* errorMessage = value.v_string.str;

            error += " (" + string(errorMessage) + ")";
        }

        throw AjRuntimeError(status, error);
    }
}

void UnifiProxyBusObject::SetProperty(const char* iface, const char* property, MsgArg& value, uint32_t timeout) const
{
    QStatus status = ProxyBusObject::SetProperty(iface, property, value, timeout);
    if (status != QStatus::ER_OK) {
        string error = string("Set property ") + iface + "." + property + " on " + ServiceName() + ObjectPath() + " failed";

        if (status == ER_BUS_REPLY_IS_ERROR_MESSAGE && value.typeId == ALLJOYN_STRING) {
            const char* errorMessage = value.v_string.str;

            error += " (" + string(errorMessage) + ")";
        }

        throw AjRuntimeError(status, error);
    }
}

string UnifiProxyBusObject::GetStringProperty(const char* interfaceName, const char* propertyName) const
{
    MsgArg argValue;

    GetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);

    const char* str;
    argValue.Get("s", &str);

    return str;
}

void UnifiProxyBusObject::SetStringProperty(const char* interfaceName, const char* propertyName, const string& value)
{
    MsgArg argValue("s", value.c_str());

    SetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);
}

uint8_t UnifiProxyBusObject::GetByteProperty(const char* interfaceName, const char* propertyName) const
{
    MsgArg argValue;

    GetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);

    uint8_t result;
    argValue.Get("y", &result);

    return result;
}

void UnifiProxyBusObject::SetByteProperty(const char* interfaceName, const char* propertyName, uint8_t value)
{
    MsgArg argValue("y", value);

    SetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);
}

int UnifiProxyBusObject::GetIntProperty(const char* interfaceName, const char* propertyName) const
{
    MsgArg argValue;

    GetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);

    int result;
    argValue.Get("i", &result);

    return result;
}

void UnifiProxyBusObject::SetIntProperty(const char* interfaceName, const char* propertyName, int value)
{
    MsgArg argValue("i", value);

    SetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);
}

bool UnifiProxyBusObject::GetBoolProperty(const char* interfaceName, const char* propertyName) const
{
    MsgArg argValue;

    GetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);

    bool result;
    argValue.Get("b", &result);

    return result;
}

void UnifiProxyBusObject::SetBoolProperty(const char* interfaceName, const char* propertyName, bool value)
{
    MsgArg argValue("b", value);

    SetProperty(interfaceName, propertyName, argValue, METHOD_CALL_TIMEOUT);
}

// Helper class for ClusterNodeObject asynchronous callback handling.
// Since ClusterNodeObject is dynamically allocated it may have been already destroyed
// when callback arrives. To fix that have this helper class with static file scope
// that should be still alive even after main() is left.

class ClusterNodeObjectListener :
    public BusAttachment::JoinSessionAsyncCB,
    public BusAttachment::LeaveSessionAsyncCB,
    private BusListener {
public:
    class Context {
    public:
        Context(const string& peerServiceName) : peerServiceName(peerServiceName) { }
        const string& PeerServiceName() const { return peerServiceName; }

    private:
        string peerServiceName;
    };

    ClusterNodeObjectListener() = default;
    ~ClusterNodeObjectListener();
    void AttachOwner(ClusterNodeObject& clusterNode);
    void RemoveOwner();
    void ConnectToPeer(const string& peerServiceName);
    void DisconnectAndRemoveToPeer(const string& peerServiceName);

    void JoinSessionCB(QStatus status, SessionId sessionId, const SessionOpts& opts, void* context) override;
    void LeaveSessionCB(QStatus status, void* context) override;

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) override;
    void LostAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) override;


private:
    ClusterNodeObject* owner = nullptr;
    set<string> peersToAdd;                                 // key = service name. Need these to ignore duplicate events during async callbacks
    mutex mutexPeersToAdd;                                  // protect access to peersToAdd
    set<string> peersToRemove;                              // key = service name.
    mutex mutexPeersToRemove;                               // protect access to peersToRemove
};

static ClusterNodeObjectListener g_ClusterNodeObjectListener;


ClusterNodeObjectListener::~ClusterNodeObjectListener()
{
    RemoveOwner();
}

void ClusterNodeObjectListener::AttachOwner(ClusterNodeObject& clusterNode)
{
    owner = &clusterNode;

    owner->Bus().RegisterBusListener(*this);
}

void ClusterNodeObjectListener::RemoveOwner()
{
    if (owner == nullptr)
        return;

    owner->Bus().UnregisterBusListener(*this);

    owner = nullptr;
}

void ClusterNodeObjectListener::JoinSessionCB(QStatus status, SessionId sessionId, const SessionOpts& opts, void* context)
{
    printf("%s: JoinSessionCB()\n", ThreadInfo());

    if (owner == nullptr || context == nullptr)
        return;

    unique_ptr<ClusterNodeObjectListener::Context> peerContext(reinterpret_cast<ClusterNodeObjectListener::Context*>(context));

    if (status != ER_OK) {
        fprintf(stderr, "JoinSessionAsync() failed for peer %s: %s\n", peerContext->PeerServiceName().c_str(), QCC_StatusText(status));
        return;
    }

    const string& peerServiceName = peerContext->PeerServiceName();

    auto peer = std::make_unique<PeerNode>(owner->App(), peerServiceName, sessionId);

    // If authentication keys on two devices are different, it is expected
    // that accessing secure interface methods and properties will fail.
    try {
        peer->Init();

        owner->AddPeer(move(peer));
    }
    catch (const std::runtime_error& ex) {
        fprintf(stderr, "Failed to access peer %s over secure interface (%s). Ignore it\n", peerServiceName.c_str(), ex.what());
    }
    catch (...) {
        fprintf(stderr, "Failed to access peer %s over secure interface. Ignore it\n", peerServiceName.c_str());
    }

    {
        std::lock_guard<std::mutex> lock(mutexPeersToAdd);

        peersToAdd.erase(peerServiceName);
    }
}

void ClusterNodeObjectListener::LeaveSessionCB(QStatus status, void* context)
{
    printf("%s: LeaveSessionCB()\n", ThreadInfo());

    if (owner == nullptr || context == nullptr)
        return;

    unique_ptr<ClusterNodeObjectListener::Context> peerContext(reinterpret_cast<ClusterNodeObjectListener::Context*>(context));

    if (status != ER_OK && status != ER_ALLJOYN_LEAVESESSION_REPLY_NO_SESSION) {
        fprintf(stderr, "LeaveJoinedSessionAsync() failed for peer %s: %s\n", peerContext->PeerServiceName().c_str(), QCC_StatusText(status));
        return;
    }
}

void ClusterNodeObjectListener::ConnectToPeer(const string& peerServiceName)
{
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    auto context = make_unique<ClusterNodeObjectListener::Context>(peerServiceName);

    QStatus status = owner->Bus().JoinSessionAsync(peerServiceName.c_str(), SERVICE_PORT, nullptr, opts, &g_ClusterNodeObjectListener, context.release());
    if (status != ER_OK)
        throw AjRuntimeError(status, string("JoinSession failed with ") + peerServiceName);

    printf("%s: JoinSessionAsync() called\n", ThreadInfo());
}

void ClusterNodeObjectListener::DisconnectAndRemoveToPeer(const string& peerServiceName)
{
    printf("DEL cluster node: %s\n", peerServiceName.c_str());

    auto peer = owner->GetPeer(peerServiceName);

    if (peer != nullptr) {
        auto context = make_unique<ClusterNodeObjectListener::Context>(peerServiceName);
        auto sessionId = peer->Proxy().GetSessionId();

        QStatus status = owner->Bus().LeaveJoinedSessionAsync(sessionId, &g_ClusterNodeObjectListener, context.release());
        if (status != ER_OK && status != ER_BUS_NOT_CONNECTED && status != ER_BUS_NO_SESSION)
            throw AjRuntimeError(status, string("LeaveJoinedSessionAsync failed with ") + peerServiceName);

        printf("%s: LeaveJoinedSessionAsync() called\n", ThreadInfo());

        owner->RemovePeer(*peer);
    }

    {
        std::lock_guard<std::mutex> lock(mutexPeersToRemove);

        peersToRemove.erase(peerServiceName);
    }
}

void ClusterNodeObjectListener::FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
{
    printf("%s: FoundAdvertisedName(): %s, transport %04x\n", ThreadInfo(), name, transport);

    if (owner == nullptr || strcmp(namePrefix, CLUSTER_NODE_SERVICE_NAME) != 0)
        return;

    const string peerServiceName(name);

    if (peerServiceName == owner->ServiceName())
        return;

    {
        std::lock_guard<std::mutex> lock(mutexPeersToAdd);

        // Ignore duplicate add events for same peer
        if (peersToAdd.find(peerServiceName) != peersToAdd.end())
            return;

        // Ignore add event for peer which we already know
        if (owner->HasPeer(peerServiceName))
            return;

        peersToAdd.emplace(peerServiceName);
    }

    ConnectToPeer(peerServiceName);
}

void ClusterNodeObjectListener::LostAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
{
    printf("%s: LostAdvertisedName(): %s, transport %04x\n", ThreadInfo(), name, transport);

    if (owner == nullptr || strcmp(namePrefix, CLUSTER_NODE_SERVICE_NAME) != 0)
        return;

    const string peerServiceName(name);

    if (peerServiceName == owner->ServiceName())
        return;

    {
        std::lock_guard<std::mutex> lock(mutexPeersToRemove);

        // Ignore duplicate remove events for same peer
        if (peersToRemove.find(peerServiceName) != peersToRemove.end())
            return;

        // Ignore remove event for peer which we do not know
        if (!owner->HasPeer(peerServiceName))
            return;

        peersToRemove.emplace(peerServiceName);
    }

    DisconnectAndRemoveToPeer(peerServiceName);
}


ClusterNodeObject::ClusterNodeObject(Application& app, const string& serviceName, const string& objectPath) :
    UnifiBusObject(app, serviceName, objectPath)
{
    BusCreateClusterNodeInterfaces(bus);
    AttachInterfaces();
    RegisterHandlers();
    RegisterBusObject();

    g_ClusterNodeObjectListener.AttachOwner(*this);
}

ClusterNodeObject::~ClusterNodeObject()
{
    g_ClusterNodeObjectListener.RemoveOwner();
}

void ClusterNodeObject::Init()
{
    app.FindAdvertisedName(CLUSTER_NODE_SERVICE_NAME);
}

void ClusterNodeObject::AttachInterfaces()
{
    intf = bus.GetInterface(CLUSTER_NODE_INTERFACE_NAME);
    AddInterface(*intf);
}

void ClusterNodeObject::RegisterHandlers()
{
    const MethodEntry methodEntries[] = {
        { intf->GetMethod("Test"), static_cast<MessageReceiver::MethodHandler>(&ClusterNodeObject::TestHandler) },
    };

    QStatus status = AddMethodHandlers(methodEntries, sizeof(methodEntries) / sizeof(methodEntries[0]));
    if (status != ER_OK) {
        throw AjRuntimeError(status, "Failed to register method handlers for ClusterNodeObject");
    }
}

// Test(in string input, out string result)
void ClusterNodeObject::TestHandler(const InterfaceDescription::Member* member, Message& msg)
{
    const MsgArg* argInput = msg->GetArg(0);
    if (argInput == nullptr)
        throw AjRuntimeError(ER_FAIL, "Unexpected message format");

    const char* input;
    QStatus status = argInput->Get("s", &input);
    if (status != ER_OK)
        throw AjRuntimeError(status, "Unexpected message format");

    printf("%s: TestHandler('%s')\n", ThreadInfo(), input);

    string reply("Reply: ");
    reply += input;

    const MsgArg argResult("s", reply.c_str());

    MethodReply(msg, &argResult, 1);
}

void ClusterNodeObject::AddPeer(unique_ptr<PeerNode> peer)
{
    printf("%s: AddPeer(): %s\n", ThreadInfo(), peer->ServiceName().c_str());

    {
        std::lock_guard<std::mutex> lock(mutexPeers);

        peers.emplace(peer->ServiceName(), move(peer));
    }
}

void ClusterNodeObject::RemovePeer(PeerNode& peer)
{
    const string peerServiceName(peer.ServiceName());

    printf("%s: RemovePeer(): %s\n", ThreadInfo(), peerServiceName.c_str());

    bool removed = false;

    {
        std::lock_guard<std::mutex> lock(mutexPeers);

        const auto it = peers.find(peerServiceName);

        if (it != peers.end()) {
            peers.erase(it);

            removed = true;
        }
    }

    if (removed) {
        printf("Remove Peer '%s'\n", peerServiceName.c_str());
    } else {
        printf("Ignore removal of unknown Peer '%s'\n", peerServiceName.c_str());
    }
}

PeerNode* ClusterNodeObject::GetPeer(const string& peerServiceName) const
{
    std::lock_guard<std::mutex> lock(mutexPeers);

    auto pit = peers.find(peerServiceName);

    return (pit != peers.end()) ? pit->second.get() : nullptr;
}

bool ClusterNodeObject::HasPeer(const string& peerServiceName) const
{
    std::lock_guard<std::mutex> lock(mutexPeers);

    return peers.find(peerServiceName) != peers.end();
}



ClusterNodeProxy::ClusterNodeProxy(Application& app, const string& serviceName, const string& objectPath, SessionId sessionId) :
    UnifiProxyBusObject(app, serviceName, objectPath, sessionId)
{
    BusCreateClusterNodeInterfaces(bus);
    AttachInterfaces();
    RegisterHandlers();
}

ClusterNodeProxy::~ClusterNodeProxy()
{
    UnregisterHandlers();
}

void ClusterNodeProxy::Init()
{
    // Can't be called within callback???

    //QStatus status = SecureConnection();
    //if (status != ER_OK)
    //    throw AjRuntimeError(status, "SecureConnection() failed");
}

void ClusterNodeProxy::AttachInterfaces()
{
    intf = bus.GetInterface(CLUSTER_NODE_INTERFACE_NAME);
    AddInterface(*intf);
}

void ClusterNodeProxy::RegisterHandlers()
{ }

void ClusterNodeProxy::UnregisterHandlers()
{ }


// Test(in string input, out string result)
string ClusterNodeProxy::Test(const string& input) const
{
    Message reply(bus);

    MsgArg argInput("s", input.c_str());

    printf("%s: Test('%s')\n", ThreadInfo(), input.c_str());

    MethodCall(CLUSTER_NODE_INTERFACE_NAME, "Test", &argInput, 1, reply, METHOD_CALL_TIMEOUT);

    const MsgArg* argResult = reply->GetArg(0);
    if (argResult == nullptr)
        throw AjRuntimeError(ER_FAIL, "Unexpected reply format");

    const char* str;
    QStatus status = argResult->Get("s", &str);
    if (status != ER_OK)
        throw AjRuntimeError(status, "Unexpected reply format");

    return str;
}


PeerNode::PeerNode(Application& app, const string& peerServiceName, SessionId sessionId) :
    proxy(app, peerServiceName, CLUSTER_NODE_OBJECT_PATH, sessionId)
{ }

void PeerNode::Init()
{
    proxy.Init();

    //SleepMsecs(1000);
    //RemoteTest("Hello");
}


Application::Application(const string& appName, const string& serviceName) :
    bus(appName.c_str(), true, 16),
    appName(appName), serviceName(serviceName), port(SERVICE_PORT),
    opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY)
{
    PreBusConnectInit();
    ConnectToAllJoynRouter();
    PostBusConnectInit();
}

Application::~Application()
{
    StopMessageBus();
}

void Application::PreBusConnectInit()
{
    StartMessageBus();
    EnablePeerSecurity();
}

void Application::PostBusConnectInit()
{
    RequestName();
    BindSessionPort();
}

void Application::ConnectToAllJoynRouter()
{
    QStatus status = bus.Connect();
    if (status != ER_OK)
        throw AjRuntimeError(status, string("Failed to connect to ") + bus.GetConnectSpec().c_str());

    printf("Connect to '%s' succeeded. Bus name %s\n", bus.GetConnectSpec().c_str(), bus.GetUniqueName().c_str());
}

void Application::StartMessageBus()
{
    QStatus status = bus.Start();
    if (status != ER_OK)
        throw AjRuntimeError(status, "BusAttachment.Start() failed");

    printf("BusAttachment started\n");
}

void Application::StopMessageBus()
{
    QStatus status = bus.Stop();
    if (status != ER_OK)
        throw AjRuntimeError(status, "BusAttachment.Stop() failed");

    status = bus.Join();
    if (status != ER_OK)
        throw AjRuntimeError(status, "BusAttachment.Join() failed");

    printf("BusAttachment stopped\n");
}

void Application::EnablePeerSecurity()
{
#ifdef OPEN_WRT
    QStatus status = bus.EnablePeerSecurity(g_AuthMechanism, this);
#else
    // In emulated environment we want to run more than one process instance on same machine.
    // Use process ID to distinguish application instances.
    string uniqueKeystoreName = appName + "_" + to_string(qcc::GetPid());

    QStatus status = bus.EnablePeerSecurity(g_AuthMechanism, this, uniqueKeystoreName.c_str(), false);
#endif

    if (status != ER_OK)
        throw AjRuntimeError(status, "EnablePeerSecurity failed");

    printf("EnablePeerSecurity succeeded\n");
}

void Application::BindSessionPort()
{
    QStatus status = bus.BindSessionPort(port, opts, *this);
    if (status != ER_OK)
        throw AjRuntimeError(status, "BindSessionPort failed");

    printf("BindSessionPort succeeded\n");
}

void Application::FindAdvertisedName(const string& name)
{
    QStatus status = bus.FindAdvertisedName(name.c_str());
    if (status != ER_OK)
        throw AjRuntimeError(status, "FindAdvertisedName failed");

    printf("FindAdvertisedName ('%s') succeeded\n", name.c_str());
}

void Application::RequestName()
{
    const uint32_t flags = DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE;

    QStatus status = bus.RequestName(serviceName.c_str(), flags);
    if (status != ER_OK && status != ER_DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER)
        throw AjRuntimeError(status, string("RequestName '") + serviceName +"' failed");

    printf("RequestName('%s') succeeded\n", serviceName.c_str());
}

void Application::AdvertiseName()
{
    QStatus status = bus.AdvertiseName(serviceName.c_str(), TRANSPORT_ANY);
    if (status != ER_OK)
        throw AjRuntimeError(status, "AdvertiseName failed");

    printf("AdvertiseName ('%s') succeeded\n", serviceName.c_str());
}

bool Application::RequestCredentials(const char* authMechanism, const char* authPeer,
    uint16_t authCount, const char* userId, uint16_t credMask, Credentials& creds)
{
    printf("%s: RequestCredentials(): peer %s, mechanism %s\n", ThreadInfo(), authPeer, authMechanism);

    if (strcmp(authMechanism, "ALLJOYN_SRP_LOGON") == 0 && authCount == 1) {
        creds.SetUserName("username");
        creds.SetPassword("password");
        return true;
    } else if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0 && authCount == 1) {
        creds.SetPassword("password");
        return true;
    }

    return false;
}

bool Application::VerifyCredentials(const char* authMechanism, const char* peerName, const Credentials& credentials)
{
    printf("%s: VerifyCredentials(): peer %s, mechanism %s\n", ThreadInfo(), peerName, authMechanism);

    if (strcmp(authMechanism, "ALLJOYN_SRP_LOGON") == 0 ||
        strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
        printf("  username %s, password %s\n", credentials.GetUserName().c_str(), credentials.GetPassword().c_str());

        return true;
    }

    return false;
}

void Application::AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success)
{
    printf("%s: AuthenticationComplete(): peer %s, mechanism %s, %s\n", ThreadInfo(), authPeer, authMechanism, success ? "successful" : "failed");
}

void Application::SecurityViolation(QStatus status, const Message& msg)
{
    printf("%s: SecurityViolation(): status %s\n", ThreadInfo(), QCC_StatusText(status));
}

bool Application::AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
{
    printf("%s: AcceptSessionJoiner(): %s\n", ThreadInfo(), joiner);

    if (sessionPort != port) {
        fprintf(stderr, "Rejecting join attempt on unexpected session port %d\n", sessionPort);
        return false;
    }

    return true;
}

void Application::SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner)
{
    printf("%s: SessionJoined(): %s, session %08x\n", ThreadInfo(), joiner, id);
    //bus.SetSessionListener(id, *this);
}


static bool g_cancelled;


void AccessPeers(ClusterNodeObject& clusterNode)
{
    static int callCount = 1;

    printf("Access peers #%d:\n", callCount);

    string hello1("Hello 1 from ");
    hello1 += clusterNode.ServiceName();

    string hello2("Hello 2 from ");
    hello2 += clusterNode.ServiceName();

    for (auto& pit : clusterNode.Peers()) {
        const string& peerServiceName = pit.first;
        PeerNode& peer = *pit.second;

        //QStatus status = peer.Proxy().SecureConnectionAsync();
        //if (status != ER_OK)
        //    throw AjRuntimeError(status, "SecureConnectionAsync() failed");

        auto result = peer.RemoteTest(hello1);

        printf("  %s: '%s'\n", peerServiceName.c_str(), result.c_str());

        auto result2 = peer.RemoteTest(hello2);

        printf("  %s: '%s'\n", peerServiceName.c_str(), result2.c_str());
    }

    callCount++;
}


int main(int argc, char** argv, char** env)
{
    AllJoynInitializer alljoyn;

    printf("AllJoyn Library version: %s\n\n", ajn::GetVersion());

    bool send = false;
    g_AuthMechanism = "ALLJOYN_SRP_LOGON";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--send") == 0) {
            send = true;
        } else if (strcmp(argv[i], "--secure") == 0) {
            g_SecureInterface = true;
        } else if (strcmp(argv[i], "--keyx") == 0) {
            g_AuthMechanism = "ALLJOYN_SRP_KEYX";
        }
    }

    printf("Using %s interface\n", g_SecureInterface ? "secure" : "unsecure");
    printf("Using %s authentication\n", g_AuthMechanism);

    try {
        string serviceName = string(CLUSTER_NODE_SERVICE_NAME) + "." + DEVICE_NAME_PREFIX + GetUniqueMacAddress();
        Application app(APPLICATION_NAME, serviceName);

        auto clusterNode = make_unique<ClusterNodeObject>(app, serviceName, CLUSTER_NODE_OBJECT_PATH);
        clusterNode->Init();

        app.AdvertiseName();

        SleepMsecs(2000);

        AccessPeers(*clusterNode);

        int i = 0;

        while (!g_cancelled) {
            SleepMsecs(10);

            if (++i == 200) {
                i = 0;

                if (send) {
                    AccessPeers(*clusterNode);
                }
            }
        }
    }
    catch (const runtime_error& ex) {
        fprintf(stderr, "Runtime error: %s\n", ex.what());
        exit(1);
    }
    catch (const exception& ex) {
        fprintf(stderr, "Generic exception: %s\n", ex.what());
        exit(2);
    }
    catch (...) {
        fprintf(stderr, "Unknown exception\n");
        exit(3);
    }

    return 0;
}
