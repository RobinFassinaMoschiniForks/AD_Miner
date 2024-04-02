from ad_miner.sources.modules.common_analysis import (
    presence_of,
    time_since,
    time_since_extraction_date,
    containsDAs,
    percentage_inferior,
    percentage_superior,
)

d = {
    "on_premise": {
        1: [],  # immediate risk
        2: [],
        3: [],
        4: [],  # handled risk
        5: [],
        -1: [],  # -1 = not tested/disabled, 5 = tested and 0 matching
    },
    "azure": {
        1: [],  # immediate risk
        2: [],
        3: [],
        4: [],  # handled risk
        5: [],
        -1: [],  # -1 = not tested/disabled, 5 = tested and 0 matching
    },
}


def rating(users, domains, computers, objects, azure, arguments):
    d["on_premise"][
        presence_of(["1"] * domains.max_da_per_domain, criticity=2, threshold=10)
    ].append("nb_domain_admins")
    d["on_premise"][presence_of(objects.can_dcsync_nodes)].append("can_dcsync")

    d["on_premise"][
        presence_of(users.users_shadow_credentials_to_non_admins, criticity=2)
    ].append("users_shadow_credentials_to_non_admins")

    d["on_premise"][
        constrainedDelegation(computers.users_constrained_delegations)
    ].append("users_constrained_delegations")
    d["on_premise"][hasPathToDA(computers.list_computers_admin_computers)].append(
        "computers_admin_of_computers"
    )
    # ANSSI says 1y, need to adapt the requests etc.
    # d[percentage_superior(domains.users_pwd_not_changed_since_1y, users.users, percentage=0.25, presence=True)].append("users_pwd_not_changed_since") # TODO CHANGE DESCRIPTION = 3MONTHS NOT 1Y

    d["on_premise"][hasPathToDA(users.users_admin_on_servers_all_data)].append(
        "server_users_could_be_admin"
    )
    d["on_premise"][
        presence_of(computers.computers_members_high_privilege_uniq)
    ].append("computers_members_high_privilege")
    d["on_premise"][presence_of(users.users_domain_admin_on_nondc)].append(
        "dom_admin_on_non_dc"
    )
    # Ghost computers
    d["on_premise"][
        percentage_superior(
            domains.computers_not_connected_since_60,
            computers.list_total_computers,
            criticity=2,
            percentage=0.5,
            presence=True,
        )
    ].append(
        "computers_last_connexion"
    )  # TODO: percentage TBD

    # RDP access | TODO: percentage TBD
    d["on_premise"][
        percentage_superior(
            users.users_rdp_access_1, users.users, criticity=3, percentage=0.5
        )
    ].append("users_rdp_access")
    d["on_premise"][
        percentage_superior(
            users.users_rdp_access_2, users.users, criticity=3, percentage=0.5
        )
    ].append("computers_list_of_rdp_users")
    # Dormant accounts

    # Threshold of 1 to exclude the false positive of container USERS containing DOMAIN ADMIN group
    d["on_premise"][
        presence_of(domains.objects_to_domain_admin, criticity=1, threshold=1)
    ].append("graph_path_objects_to_da")

    d["on_premise"][presence_of(users.unpriv_to_dnsadmins, criticity=2)].append(
        "unpriv_to_dnsadmins"
    )

    d["on_premise"][
        presence_of(users.vuln_permissions_adminsdholder, criticity=1)
    ].append("vuln_permissions_adminsdholder")

    d["on_premise"][presence_of(users.objects_to_operators_member)].append(
        "objects_to_operators_member"
    )

    d["on_premise"][presence_of(domains.objects_to_ou_handlers)].append(
        "graph_path_objects_to_ou_handlers"
    )
    d["on_premise"][presence_of(domains.da_to_da)].append("da_to_da")

    d["on_premise"][presence_of(domains.unpriv_users_to_GPO_parsed.items())].append(
        "users_GPO_access"
    )

    d["on_premise"][1 if domains.total_dangerous_paths > 0 else 5].append(
        "dangerous_paths"
    )

    d["on_premise"][2 if users.number_group_ACL_anomaly > 0 else 5].append(
        "anomaly_acl"
    )

    d["on_premise"][presence_of(users.has_sid_history, 2)].append("has_sid_history")
    d["on_premise"][
        rate_cross_domain_privileges(
            domains.cross_domain_local_admin_accounts,
            domains.cross_domain_domain_admin_accounts,
        )
    ].append("cross_domain_admin_privileges")

    d["on_premise"][
        presence_of([ude for ude in users.guest_accounts if ude[-1]])
    ].append("guest_accounts")
    d["on_premise"][
        rate_admincount(
            users.unpriviledged_users_with_admincount, users.users_nb_domain_admins
        )
    ].append("up_to_date_admincount"),
    d["on_premise"][
        presence_of(
            [
                dic
                for dic in users.users_nb_domain_admins
                if "Protected Users" not in dic["admin type"]
            ]
        )
    ].append("privileged_accounts_outside_Protected_Users"),

    d["on_premise"][
        rate_pre_windows_2000(users.pre_windows_2000_compatible_access_group)
    ].append("pre_windows_2000_compatible_access_group")

    # Azure
    d["azure"][presence_of(azure.azure_users_paths_high_target, 3)].append(
        "azure_users_paths_high_target"
    )
    d["azure"][presence_of(azure.azure_ms_graph_controllers, 1)].append(
        "azure_ms_graph_controllers"
    )
    d["azure"][presence_of(azure.azure_aadconnect_users, 3)].append(
        "azure_aadconnect_users"
    )
    d["azure"][presence_of(azure.azure_admin_on_prem, 1)].append("azure_admin_on_prem")
    d["azure"][presence_of(azure.azure_roles_entry_nodes, 2)].append("azure_roles")
    d["azure"][presence_of(azure.reset_passwd.keys(), 2)].append("azure_reset_passwd")
    d["azure"][presence_of(azure.azure_last_passwd_change_strange, 3)].append(
        "azure_last_passwd_change"
    )
    d["azure"][presence_of(azure.azure_dormant_accounts, 3)].append(
        "azure_dormant_accounts"
    )
    d["azure"][presence_of(azure.azure_accounts_disabled_on_prem, 3)].append(
        "azure_accounts_disabled_on_prem"
    )
    d["azure"][presence_of(azure.azure_accounts_not_found_on_prem, 3)].append(
        "azure_accounts_not_found_on_prem"
    )
    d["azure"][1 if azure.azure_total_cross_ga_da_compromission > 0 else 5].append(
        "azure_cross_ga_da"
    )

    return d


def rate_cross_domain_privileges(nb_local_priv, nb_da_priv):
    if nb_da_priv > 0:
        return 1
    elif nb_local_priv > 0:
        return 2
    else:
        return 5


def rate_admincount(unpriviledged_users_with_admincount, users_nb_domain_admins):
    if unpriviledged_users_with_admincount is None or users_nb_domain_admins is None:
        return -1
    for da_dic in users_nb_domain_admins:
        if not da_dic["admincount"]:
            return 1
    if len(unpriviledged_users_with_admincount) > 0:
        return 3
    return 5


def rate_pre_windows_2000(pre_windows_2000_compatible_access_group):
    if pre_windows_2000_compatible_access_group is None:
        return -1
    if True in ["1-5-7" in dni[2] for dni in pre_windows_2000_compatible_access_group]:
        return 2
    elif len(pre_windows_2000_compatible_access_group) > 0:
        return 3
    else:
        return 5
