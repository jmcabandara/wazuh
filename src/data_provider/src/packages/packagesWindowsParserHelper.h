/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGES_WINDOWS_PARSER_HELPER_H
#define _PACKAGES_WINDOWS_PARSER_HELPER_H

#include <regex>
#include "json.hpp"
#include "registryHelper.h"
#include "stringHelper.h"


namespace PackageWindowsHelper
{
    constexpr auto WIN_REG_HOTFIX {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"};
    constexpr auto VISTA_REG_HOTFIX {"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"};

    static std::string extractHFValue(std::string input)
    {
        constexpr auto KB_FORMAT_REGEX_STR { "(KB+[0-9]{6,})"};
        static std::regex rex{KB_FORMAT_REGEX_STR};
        std::string ret;
        input = Utils::toUpperCase(input);
        std::smatch match;
<<<<<<< HEAD

        if (std::regex_search(input, match, std::regex(KB_FORMAT_REGEX_STR)))
=======
        if (std::regex_search(input, match, rex))
>>>>>>> 4.2
        {
            // KB format is correct
            ret = match[1];
        }

        return ret;
    }

    static void getHotFixFromReg(const HKEY key, const std::string& subKey, nlohmann::json& data)
    {
        try
        {
            std::set<std::string> hotfixes;
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
<<<<<<< HEAD
            const auto packages{root.enumerate()};

            for (const auto& package : packages)
=======
            const auto callback
>>>>>>> 4.2
            {
                [&key, &subKey, &hotfixes](const std::string& package)
                {
<<<<<<< HEAD
                    std::string value;
                    Utils::Registry packageReg{key, subKey + "\\" + package, KEY_WOW64_64KEY | KEY_READ};

                    if (packageReg.string("InstallLocation", value))
                    {
                        const auto hfValue { extractHFValue(value) };

=======
                    if (Utils::startsWith(package, "Package_"))
                    {
                        auto hfValue { extractHFValue(package) };
>>>>>>> 4.2
                        if (!hfValue.empty())
                        {
                            hotfixes.insert(std::move(hfValue));
                        }
                        else if (package.find("RollupFix") != std::string::npos)
                        {
                            std::string value;
                            Utils::Registry packageReg{key, subKey + "\\" + package, KEY_WOW64_64KEY | KEY_READ};
                            if (packageReg.string("InstallLocation", value))
                            {
                                auto rollUpValue { extractHFValue(value) };
                                if (!rollUpValue.empty())
                                {
                                    hotfixes.insert(std::move(rollUpValue));
                                }
                            }
                        }
                    }
                }
<<<<<<< HEAD
            }

            for (const auto& hotfix : hotfixes)
=======
            };
            root.enumerate(callback);
            for (auto& hotfix : hotfixes)
>>>>>>> 4.2
            {
                nlohmann::json hotfixValue;
                hotfixValue["hotfix"] = std::move(hotfix);
                data.push_back(std::move(hotfixValue));
            }
        }
        catch (...)
        {
        }
    }

    static void getHotFixFromRegNT(const HKEY key, const std::string& subKey, nlohmann::json& data)
    {
        try
        {
            std::set<std::string> hotfixes;
<<<<<<< HEAD
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            const auto packages{root.enumerate()};

            for (const auto& package : packages)
            {
                const auto hfValue { extractHFValue(package) };

                if (!hfValue.empty())
=======
            const auto callback
            {
                [&key, &subKey, &hotfixes](const std::string& package)
>>>>>>> 4.2
                {
                    auto hfValue { extractHFValue(package) };
                    if (!hfValue.empty())
                    {
                        hotfixes.insert(std::move(hfValue));
                    }
                }
<<<<<<< HEAD
            }

            for (const auto& hotfix : hotfixes)
=======
            };
            Utils::Registry root{key, subKey, KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ};
            root.enumerate(callback);
            for (auto& hotfix : hotfixes)
>>>>>>> 4.2
            {
                nlohmann::json hotfixValue;
                hotfixValue["hotfix"] = std::move(hotfix);
                data.push_back(std::move(hotfixValue));
            }
        }
        catch (...)
        {
        }
    }
};

#endif // _PACKAGES_WINDOWS_PARSER_HELPER_H
