// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "analyzer.hpp"

#include "histogram.hpp"
#include "main.hpp"
#include "sensorhelper.hpp"
#include "views.hpp"
#include "xmlparse.hpp"

#include <unistd.h>

#include <atomic>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>

int AcquireBus(sd_bus** ret);

extern SensorSnapshot* g_sensor_snapshot;
extern DBusConnectionSnapshot* g_connection_snapshot;
extern sd_bus* g_bus;
extern SensorDetailView* g_sensor_detail_view;
extern FooterView* g_footer_view;

static std::unordered_map<uint64_t, uint64_t>
    in_flight_methodcalls; // serial => microseconds
uint64_t Microseconds()
{
    long us;  // usec
    time_t s; // Seconds
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    s = spec.tv_sec;
    us = round(spec.tv_nsec / 1000); // Convert nanoseconds to milliseconds
    if (us > 999999)
    {
        s++;
        us = 0;
    }
    return s * 1000000 + us;
}

int g_update_interval_millises = 2000;
int GetSummaryIntervalInMillises()
{
    return g_update_interval_millises;
}

bool DBusTopSortFieldIsNumeric(DBusTopSortField field)
{
    switch (field)
    {
        case kSender:
        case kDestination:
        case kInterface:
        case kPath:
        case kMember:
        case kSenderCMD:
            return false;
        case kSenderPID:
        case kMsgPerSec:
        case kAverageLatency:
            return true;
    }
    return false;
}

namespace dbus_top_analyzer
{
DBusTopStatistics g_dbus_statistics;
Histogram<float> g_mc_time_histogram;
std::unordered_map<uint32_t, uint64_t> in_flight_methodcalls;
std::atomic<bool> g_program_done = false;
std::chrono::time_point<std::chrono::steady_clock> g_last_update;
DBusTopStatisticsCallback g_callback;
void SetDBusTopStatisticsCallback(DBusTopStatisticsCallback cb)
{
    g_callback = cb;
}

int UserInputThread()
{
    return 0;
}

std::string g_dbus_top_conn = " ";
void SetDBusTopConnectionForMonitoring(const std::string& conn)
{
    g_dbus_top_conn = conn;
}

// Performs one step of analysis
void Process()
{
    std::chrono::time_point<std::chrono::steady_clock> t =
        std::chrono::steady_clock::now();
    std::chrono::time_point<std::chrono::steady_clock> next_update =
        g_last_update + std::chrono::milliseconds(g_update_interval_millises);
    if (t >= next_update)
    {
        float seconds_since_last_sample =
            std::chrono::duration_cast<std::chrono::microseconds>(t -
                                                                  g_last_update)
                .count() /
            1000000.0f;
        g_dbus_statistics.seconds_since_last_sample_ =
            seconds_since_last_sample;
        // Update snapshot
        if (g_callback)
        {
            g_callback(&g_dbus_statistics, &g_mc_time_histogram);
        }
        g_dbus_statistics.Reset();
        g_last_update = t;
    }
}

void Finish()
{
    g_program_done = true;
}

std::vector<std::string> FindAllObjectPathsForService(
    sd_bus* bus, const std::string& service,
    std::function<void(const std::string&, const std::vector<std::string>&)>
        on_interface_cb)
{
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m, *reply;
    std::vector<std::string> paths; // Current iteration
    std::vector<std::string>
        all_obj_paths; // All object paths under the supervision of ObjectMapper
    paths.push_back("/");
    // busctl call xyz.openbmc_project.ObjectMapper        /
    // org.freedesktop.DBus.Introspectable        Introspect
    while (!paths.empty())
    {
        // printf("%d paths to explore, total %d paths so far\n",
        // int(paths.size()), int(all_obj_paths.size()));
        std::vector<std::string> new_paths;
        for (const std::string& obj_path : paths)
        {
            all_obj_paths.push_back(obj_path);
            int r = sd_bus_message_new_method_call(
                bus, &m, service.c_str(), obj_path.c_str(),
                "org.freedesktop.DBus.Introspectable", "Introspect");
            if (r < 0)
            {
                continue;
            }
            r = sd_bus_call(bus, m, 0, &err, &reply);
            if (r < 0)
            {
                continue;
            }
            const char* sig = sd_bus_message_get_signature(reply, 0);
            if (!strcmp(sig, "s"))
            {
                const char* s;
                int r = sd_bus_message_read(reply, "s", &s);
                if (r < 0)
                {
                    continue;
                }
                else
                {
                    XMLNode* t = ParseXML(std::string(s));
                    std::vector<std::string> ch = t->GetChildNodeNames();
                    if (on_interface_cb != nullptr)
                    {
                        on_interface_cb(obj_path, t->GetInterfaceNames());
                    }
                    DeleteTree(t);
                    for (const std::string& cn : ch)
                    {
                        std::string ch_path = obj_path;
                        if (obj_path.back() == '/')
                        {}
                        else
                            ch_path.push_back('/');
                        ch_path += cn;
                        new_paths.push_back(ch_path);
                    }
                }
            }
        }
        paths = new_paths;
    }
    return all_obj_paths;
}

void ListAllSensors(sd_bus* bus, DBusConnectionSnapshot** cxn_snapshot,
                    SensorSnapshot** sensor_snapshot)
{
    // Craete new snapshots
    (*cxn_snapshot) = new DBusConnectionSnapshot();
    (*sensor_snapshot) = new SensorSnapshot(*cxn_snapshot);

    g_footer_view->SetStatusString("1. Listing DBus Names");
    DBusTopUpdateFooterView();
    char** names;
    int r = sd_bus_list_names(bus, &names, nullptr);
    std::vector<std::string> services;
    std::vector<int> pids;
    std::vector<std::string> comms;
    for (char** ptr = names; ptr && *ptr; ++ptr)
    {
        services.push_back(*ptr);
        free(*ptr);
    }
    free(names);

    g_footer_view->SetStatusString("2. Getting Creds");
    DBusTopUpdateFooterView();
    size_t N = services.size();
    for (size_t i = 0; i < N; i++)
    {
        if (i == N - 1 || (i % 100) == 99)
        {
            g_footer_view->SetStatusString("2. Getting Creds " +
                                           std::to_string(i + 1) + "/" +
                                           std::to_string(N));
            DBusTopUpdateFooterView();
        }
        const std::string& service = services[i];
        sd_bus_creds* creds = nullptr;
        r = sd_bus_get_name_creds(bus, services[i].c_str(),
                                  SD_BUS_CREDS_AUGMENT | SD_BUS_CREDS_EUID |
                                      SD_BUS_CREDS_PID | SD_BUS_CREDS_COMM |
                                      SD_BUS_CREDS_UNIQUE_NAME |
                                      SD_BUS_CREDS_UNIT | SD_BUS_CREDS_SESSION |
                                      SD_BUS_CREDS_DESCRIPTION,
                                  &creds);
        // PID
        int pid = INVALID;
        if (r < 0)
        {}
        else
        {
            r = sd_bus_creds_get_pid(creds, &pid);
        }
        pids.push_back(pid);
        // comm
        std::string comm;
        if (pid != INVALID)
        {
            std::ifstream ifs("/proc/" + std::to_string(pid) + "/cmdline");
            std::string line;
            std::getline(ifs, line);
            for (char c : line)
            {
                if (c < 32 || c >= 127)
                    c = ' ';
                comm.push_back(c);
            }
        }
        comms.push_back(comm);
        // unique name, also known as "Connection"
        std::string connection;
        const char* u;
        r = sd_bus_creds_get_unique_name(creds, &u);
        if (r >= 0)
        {
            connection = u;
        }
        std::string unit;
        r = sd_bus_creds_get_unit(creds, &u);
        if (r >= 0)
        {
            unit = u;
        }
        (*cxn_snapshot)->AddConnection(service, connection, comm, unit, pid);
    }
    // busctl call xyz.openbmc_project.ObjectMapper /
    // org.freedesktop.DBus.Introspectable Introspect

    g_footer_view->SetStatusString("3. Examine objects in ObjectMapper");
    std::vector<std::string> all_obj_paths = FindAllObjectPathsForService(
        bus, "xyz.openbmc_project.ObjectMapper", nullptr);
    N = all_obj_paths.size();
    sd_bus_error err = SD_BUS_ERROR_NULL;
    sd_bus_message *m, *reply;
    for (size_t i = 0; i < N; i++)
    {
        if (i % 100 == 99 || i == N - 1)
        {
            g_footer_view->SetStatusString(
                "3. Examine objects in ObjectMapper " + std::to_string(i + 1) +
                "/" + std::to_string(N));
            DBusTopUpdateFooterView();
        }

        const std::string& p = all_obj_paths[i];
        if (IsSensorObjectPath(p))
        {
            err = SD_BUS_ERROR_NULL;
            r = sd_bus_message_new_method_call(
                bus, &m, "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetObject");
            if (r < 0)
            {
                continue;
            }
            r = sd_bus_message_append_basic(m, 's', p.c_str());
            if (r < 0)
            {
                continue;
            }
            // empty array
            r = sd_bus_message_open_container(m, 'a', "s");
            if (r < 0)
            {
                continue;
            }
            r = sd_bus_message_close_container(m);
            if (r < 0)
            {
                continue;
            }
            r = sd_bus_call(bus, m, 0, &err, &reply);
            if (r < 0)
            {}
            const char* sig = sd_bus_message_get_signature(reply, 0);
            if (!strcmp(sig, "a{sas}"))
            {
                r = sd_bus_message_enter_container(reply, 'a', "{sas}");
                if (r < 0)
                {
                    continue;
                }
                while (true)
                {
                    r = sd_bus_message_enter_container(
                        reply, SD_BUS_TYPE_DICT_ENTRY, "sas");
                    if (r < 0)
                    {
                        goto DONE;
                    }
                    else if (r == 0)
                    {}
                    else
                    {
                        // The following 2 correspond to `interface_map` in
                        // phosphor-mapper
                        const char* interface_map_first;
                        r = sd_bus_message_read_basic(reply, 's',
                                                      &interface_map_first);
                        if (r < 0)
                        {
                            goto DONE;
                        }
                        r = sd_bus_message_enter_container(reply, 'a', "s");
                        if (r < 0)
                        {
                            goto DONE;
                        }
                        bool has_value_interface = false;
                        while (true)
                        {
                            const char* interface_map_second;
                            r = sd_bus_message_read_basic(
                                reply, 's', &interface_map_second);
                            if (r < 0)
                            {}
                            else if (r == 0)
                                break;
                            else
                            {
                                if (!strcmp(interface_map_second,
                                            "xyz.openbmc_project.Sensor.Value"))
                                {
                                    has_value_interface = true;
                                }
                            }
                        }
                        if (has_value_interface)
                        {
                            (*sensor_snapshot)
                                ->SetSensorVisibleFromObjectMapper(
                                    std::string(interface_map_first), p);
                        }
                        r = sd_bus_message_exit_container(reply);
                    }
                    r = sd_bus_message_exit_container(reply);
                }
                r = sd_bus_message_exit_container(reply);
            }
        DONE:
        {}
        }
    }

    g_footer_view->SetStatusString("4. List Associations in ObjectMapper");
    DBusTopUpdateFooterView();
    err = SD_BUS_ERROR_NULL;
    r = sd_bus_message_new_method_call(
        bus, &m, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_append_basic(m, 's', "/");
    if (r < 0)
    {
        assert(0);
    }
    const int zero = 0;
    r = sd_bus_message_append_basic(m, 'i', &zero);
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_open_container(m, 'a', "s");
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_append_basic(m, 's', "xyz.openbmc_project.Association");
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_close_container(m);
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_call(bus, m, 0, &err, &reply);
    if (r < 0)
    {
        assert(0);
    }
    const char* sig = sd_bus_message_get_signature(reply, 0);
    if (strcmp(sig, "as"))
    {
        assert(0);
    }
    r = sd_bus_message_enter_container(reply, 'a', "s");
    if (r < 0)
    {
        assert(0);
    }
    std::set<std::string> assoc_paths;
    while (true)
    {
        const char* p;
        r = sd_bus_message_read_basic(reply, 's', &p);
        if (r <= 0)
            break;
        else
        {
            assoc_paths.insert(p);
        }
    }
    r = sd_bus_message_exit_container(reply);
    if (r < 0)
    {
        assert(0);
    }

    size_t idx = 0;
    for (const std::string& assoc_path : assoc_paths)
    {
        if (idx % 100 == 99 || idx == N - 1)
        {
            g_footer_view->SetStatusString(
                "4. List Associations in ObjectMapper " +
                std::to_string(idx + 1) + "/" + std::to_string(N));
            DBusTopUpdateFooterView();
        }
        ++idx;
        err = SD_BUS_ERROR_NULL;
        r = sd_bus_message_new_method_call(
            bus, &m, "xyz.openbmc_project.ObjectMapper", assoc_path.c_str(),
            "org.freedesktop.DBus.Properties", "Get");
        r = sd_bus_message_append_basic(m, 's',
                                        "xyz.openbmc_project.Association");
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_message_append_basic(m, 's', "endpoints");
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_call(bus, m, 0, &err, &reply);
        if (r < 0)
        {
            // The object may not have any endpoints
            continue;
        }
        const char* sig = sd_bus_message_get_signature(reply, 0);
        if (strcmp(sig, "v"))
        {
            assert(0);
        }
        r = sd_bus_message_enter_container(reply, 'v', "as");
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_message_enter_container(reply, 'a', "s");
        if (r < 0)
        {
            assert(0);
        }
        std::set<std::string> entries;
        while (true)
        {
            const char* p;
            r = sd_bus_message_read_basic(reply, 's', &p);
            if (r <= 0)
                break;
            entries.insert(p);
        }
        r = sd_bus_message_exit_container(reply);
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_message_exit_container(reply);
        if (r < 0)
        {
            assert(0);
        }

        (*sensor_snapshot)->AddAssociationEndpoints(assoc_path, entries);
    }

    g_footer_view->SetStatusString("5. Find Association Definitions");
    DBusTopUpdateFooterView();

    err = SD_BUS_ERROR_NULL;
    r = sd_bus_message_new_method_call(
        bus, &m, "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    std::vector<std::pair<std::string, std::string>>
        services_and_objects; // Record the Associations from those pairs
    r = sd_bus_message_append_basic(m, 's', "/");
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_append_basic(m, 'i', &zero);
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_open_container(m, 'a', "s");
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_append_basic(
        m, 's', "xyz.openbmc_project.Association.Definitions");
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_message_close_container(m);
    if (r < 0)
    {
        assert(0);
    }
    r = sd_bus_call(bus, m, 0, &err, &reply);
    if (r < 0)
    {
        assert(0);
    }
    sig = sd_bus_message_get_signature(reply, 0);
    if (strcmp(sig, "a{sa{sas}}"))
    {
        assert(0);
    }
    r = sd_bus_message_enter_container(reply, 'a', "{sa{sas}}");
    if (r <= 0)
    {
        assert(0);
    }

    idx = 0;
    N = services_and_objects.size();
    while (true)
    {
        if (idx % 100 == 99 || idx == N - 1)
        {
            g_footer_view->SetStatusString("5. Find Association Definitions " +
                                           std::to_string(idx + 1) + "/" +
                                           std::to_string(N));
            DBusTopUpdateFooterView();
        }
        r = sd_bus_message_enter_container(reply, 'e', "sa{sas}");
        if (r <= 0)
        {
            break;
        }              // e denotes 'dict entry'
        const char* p; // path
        r = sd_bus_message_read_basic(reply, 's', &p);
        if (r <= 0)
            break;
        r = sd_bus_message_enter_container(reply, 'a', "{sas}");
        if (r <= 0)
        {
            assert(0);
        }
        while (true)
        {
            const char* service; // service
            r = sd_bus_message_enter_container(reply, 'e', "sas");
            if (r <= 0)
            {
                break;
            }
            r = sd_bus_message_read_basic(reply, 's', &service);
            if (r < 0)
            {
                assert(0);
            }
            services_and_objects.emplace_back(std::string(service),
                                              std::string(p));
            r = sd_bus_message_enter_container(reply, 'a', "s");
            if (r <= 0)
            {
                assert(0);
            }
            while (true)
            {
                const char* iface;
                r = sd_bus_message_read_basic(reply, 's', &iface);
                if (r <= 0)
                {
                    break;
                }
            }
            r = sd_bus_message_exit_container(reply);
            if (r < 0)
            {
                assert(0);
            } // exit a
            r = sd_bus_message_exit_container(reply);
            if (r < 0)
            {
                assert(0);
            } // exit e
        }
        r = sd_bus_message_exit_container(reply);
        if (r < 0)
        {
            assert(0);
        } // exit a
        r = sd_bus_message_exit_container(reply);
        if (r < 0)
        {
            assert(0);
        } // exit e
    }
    r = sd_bus_message_exit_container(reply);
    if (r < 0)
    {
        assert(0);
    } // exit a

    idx = 0;
    N = services_and_objects.size();
    for (const std::pair<std::string, std::string>& serv_and_obj :
         services_and_objects)
    {
        if (idx % 100 == 99 || idx == N - 1)
        {
            g_footer_view->SetStatusString(
                "6. Find Associations of Endpoints " + std::to_string(idx + 1) +
                "/" + std::to_string(N));
            DBusTopUpdateFooterView();
        }
        ++idx;
        err = SD_BUS_ERROR_NULL;
        r = sd_bus_message_new_method_call(
            bus, &m, serv_and_obj.first.c_str(), serv_and_obj.second.c_str(),
            "org.freedesktop.DBus.Properties", "Get");
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_message_append_basic(
            m, 's', "xyz.openbmc_project.Association.Definitions");
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_message_append_basic(m, 's', "Associations");
        if (r < 0)
        {
            assert(0);
        }
        r = sd_bus_call(bus, m, 0, &err, &reply);
        if (r <= 0)
        {
            continue;
        }
        sig = sd_bus_message_get_signature(reply, 0);
        if (strcmp(sig, "v"))
        {
            assert(0);
        }
        r = sd_bus_message_enter_container(reply, 'v', "a(sss)");
        if (r <= 0)
        {
            continue;
        }
        r = sd_bus_message_enter_container(reply, 'a', "(sss)");
        if (r <= 0)
        {
            continue;
        }
        while (true)
        {
            r = sd_bus_message_enter_container(reply, 'r', "sss");
            if (r <= 0)
            {
                break;
            } // struct
            const char *forward, *reverse, *endpoint;
            r = sd_bus_message_read_basic(reply, 's', &forward);
            if (r < 0)
            {
                break;
            }
            r = sd_bus_message_read_basic(reply, 's', &reverse);
            if (r < 0)
            {
                assert(0);
            }
            r = sd_bus_message_read_basic(reply, 's', &endpoint);
            if (r < 0)
            {
                assert(0);
            }
            (*sensor_snapshot)
                ->AddAssociationDefinition(
                    serv_and_obj.second, std::string(forward),
                    std::string(reverse), std::string(endpoint));
            r = sd_bus_message_exit_container(reply);
            if (r < 0)
            {
                assert(0);
            } // exit struct
        }
        r = sd_bus_message_exit_container(reply);
        if (r < 0)
        {
            assert(0);
        } // exit a
        r = sd_bus_message_exit_container(reply);
        if (r < 0)
        {
            assert(0);
        } // exit v
    }

    g_footer_view->SetStatusString("7. Check HWMon DBus objects");
    DBusTopUpdateFooterView();
    for (size_t i = 0; i < comms.size(); i++)
    {
        if (i % 100 == 99 || i == N - 1)
        {
            g_footer_view->SetStatusString("7. Check HWMon DBus objects " +
                                           std::to_string(i + 1) + "/" +
                                           std::to_string(N));
            DBusTopUpdateFooterView();
        }
        const std::string& comm = comms[i];
        const std::string& service = services[i];
        if (comm.find("phosphor-hwmon-readd") != std::string::npos &&
            !IsUniqueName(service))
        {
            // printf("Should introspect %s\n", service.c_str());
            std::vector<std::string> objpaths =
                FindAllObjectPathsForService(bus, service, nullptr);
            for (const std::string& op : objpaths)
            {
                if (IsSensorObjectPath(op))
                {
                    (*sensor_snapshot)->SetSensorVisibleFromHwmon(service, op);
                }
            }
        }
    }

    g_footer_view->SetStatusString("DBus object scan complete");
    DBusTopUpdateFooterView();
}
} // namespace dbus_top_analyzer

void DBusTopStatistics::OnNewDBusMessage(const char* sender,
                                         const char* destination,
                                         const char* interface,
                                         const char* path, const char* member,
                                         const char type, sd_bus_message* m)
{
    num_messages_++;
    std::vector<std::string> keys;

    std::string sender_orig = CheckAndFixNullString(sender);
    std::string dest_orig = CheckAndFixNullString(destination);
    // For method return messages, we actually want to show the sender
    // and destination of the original method call, so we swap the
    // sender and destination
    if (type == 2)
    { // DBUS_MESSAGE_TYPE_METHOD_METHOD_RETURN
        std::swap(sender_orig, dest_orig);
    }

    // Special case: when PID == 1 (init), the DBus unit would be systemd.
    // It seems it was not possible to obtain the connection name of systemd
    // so we manually set it here.
    const int sender_orig_pid =
        g_connection_snapshot->GetConnectionPIDFromNameOrUniqueName(
            sender_orig);

    if (sender_orig_pid == 1)
    {
        sender_orig = "systemd";
    }
    const int dest_orig_pid =
        g_connection_snapshot->GetConnectionPIDFromNameOrUniqueName(dest_orig);
    if (dest_orig_pid == 1)
    {
        dest_orig = "systemd";
    }

    for (DBusTopSortField field : fields_)
    {
        switch (field)
        {
            case kSender:
                keys.push_back(sender_orig);
                break;
            case kDestination:
                keys.push_back(dest_orig);
                break;
            case kInterface:
                keys.push_back(CheckAndFixNullString(interface));
                break;
            case kPath:
                keys.push_back(CheckAndFixNullString(path));
                break;
            case kMember:
                keys.push_back(CheckAndFixNullString(member));
                break;
            case kSenderPID:
            {
                if (sender_orig_pid != INVALID)
                {
                    keys.push_back(std::to_string(sender_orig_pid));
                }
                else
                {
                    keys.push_back("(unknown)");
                }
                break;
            }
            case kSenderCMD:
            {
                keys.push_back(
                    g_connection_snapshot->GetConnectionCMDFromNameOrUniqueName(
                        sender_orig));
                break;
            }
            case kMsgPerSec:
            case kAverageLatency:
                break; // Don't populate "keys" using these 2 fields
        }
    }
    // keys = combination of fields of user's choice

    if (stats_.count(keys) == 0)
    {
        stats_[keys] = DBusTopComputedMetrics();
    }
    // Need to update msg/s regardless
    switch (type)
    {
        case 1: // DBUS_MESSAGE_TYPE_METHOD_CALL
            stats_[keys].num_method_calls++;
            break;
        case 2: // DBUS_MESSAGE_TYPE_METHOD_METHOD_RETURN
            stats_[keys].num_method_returns++;
            break;
        case 3: // DBUS_MESSAGE_TYPE_ERROR
            stats_[keys].num_errors++;
            break;
        case 4: // DBUS_MESSAGE_TYPE_SIGNAL
            stats_[keys].num_signals++;
            break;
    }
    // Update global latency histogram
    // For method call latency
    if (type == 1) // DBUS_MESSAGE_TYPE_METHOD_CALL
    {
        uint64_t serial; // serial == cookie
        sd_bus_message_get_cookie(m, &serial);
        in_flight_methodcalls[serial] = Microseconds();
    }
    else if (type == 2) // DBUS_MESSAGE_TYPE_MEHOTD_RETURN
    {
        uint64_t reply_serial = 0; // serial == cookie
        sd_bus_message_get_reply_cookie(m, &reply_serial);
        if (in_flight_methodcalls.count(reply_serial) > 0)
        {
            float dt_usec = Microseconds() -
                            in_flight_methodcalls[reply_serial];
            in_flight_methodcalls.erase(reply_serial);
            dbus_top_analyzer::g_mc_time_histogram.AddSample(dt_usec);

            // Add method call count and total latency to the corresponding key
            stats_[keys].total_latency_usec += dt_usec;
        }
    }
    // For meaning of type see here
    // https://dbus.freedesktop.org/doc/api/html/group__DBusProtocol.html#ga4a9012edd7f22342f845e98150aeb858
    switch (type)
    {
        case 1:
            num_mc_++;
            break;
        case 2:
            num_mr_++;
            break;
        case 3:
            num_error_++;
            break;
        case 4:
            num_sig_++;
            break;
    }
}
