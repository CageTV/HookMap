// The few SKSE64 plugin-API types HookMap needs, copied in layout only (no SKSE or CommonLib headers, no game structures).
#pragma once
#include <cstdint>

namespace skse
{
    using PluginHandle = uint32_t;

    struct Interface
    {
        uint32_t skseVersion;
        uint32_t runtimeVersion;
        uint32_t editorVersion;
        uint32_t isEditor;
        void* (*QueryInterface)(uint32_t id);
        PluginHandle (*GetPluginHandle)();
        uint32_t (*GetReleaseIndex)();
        const void* (*GetPluginInfo)(const char* name);
    };

    constexpr uint32_t kInterface_Messaging = 5;

    struct Message
    {
        const char* sender;
        uint32_t type;
        uint32_t dataLen;
        void* data;
    };

    struct MessagingInterface
    {
        uint32_t interfaceVersion;
        bool (*RegisterListener)(PluginHandle listener, const char* sender, void (*handler)(Message*));
        bool (*Dispatch)(PluginHandle sender, uint32_t messageType, void* data, uint32_t dataLen, const char* receiver);
        void* (*GetEventDispatcher)(uint32_t dispatcherId);
    };

    // Messages SKSE sends to every listener.
    constexpr uint32_t kMessage_PostLoad = 0;
    constexpr uint32_t kMessage_PostPostLoad = 1;
    constexpr uint32_t kMessage_PreLoadGame = 2;
    constexpr uint32_t kMessage_PostLoadGame = 3;
    constexpr uint32_t kMessage_InputLoaded = 6;
    constexpr uint32_t kMessage_NewGame = 7;
    constexpr uint32_t kMessage_DataLoaded = 8;

    struct PluginInfo
    {
        uint32_t infoVersion;
        const char* name;
        uint32_t version;
    };

    struct PluginVersionData
    {
        uint32_t dataVersion;
        uint32_t pluginVersion;
        char name[256];
        char author[256];
        char supportEmail[252];
        uint32_t versionIndependenceEx;
        uint32_t versionIndependence;
        uint32_t compatibleVersions[16];
        uint32_t seVersionRequired;
    };
    static_assert(sizeof(PluginVersionData) == 848);
}
