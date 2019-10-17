import re
import sys

from params import *

argument_len = len(sys.argv)
if argument_len == 1:
    print("Please provide project name and A10 config file!")
    sys.exit(1)
elif argument_len == 2:
    project_name = "A10_migration"
else:
    project_name = sys.argv[2]

file = open(sys.argv[1], 'r')
logfile = open(project_name+"_logfile.txt", 'w+')


def fun_clear_cfg_and_dicts(cfg):
    for i in range(10):
        cfg = re.sub(re.compile(r'^!\n^\n', re.MULTILINE), '!\n', cfg)
        cfg = re.sub(re.compile(r'^!\n^!\n', re.MULTILINE), '!\n', cfg)
        cfg = re.sub(re.compile(r'^\n^\n', re.MULTILINE), '', cfg)
    int_dict.clear()
    lacp_dict.clear()
    real_dict.clear()
    group_dict.clear()
    vlan_dict.clear()
    route_dict.clear()
    health_dict.clear()
    nwclass_dict.clear()
    virt_dict.clear()
    vip_list.clear()
    gw_dict.clear()
    tmpl_dict.clear()
    float_dict.clear()
    arp_dict.clear()
    priority_dict.clear()
    return cfg


def fun_unhandeled(section, log):
    while log[0] == " ":
        log = log[1:]
    logfile.write("\nUnhandeled command found in " + section + " config:\n\t" + log + "\n")


def fun_dict_append(key, value, var_dict):
    tmp = var_dict
    for i in range(len(key)):
        if i == len(key) - 1:
            tmp[key[i]] = value
        if key[i] in tmp:
            tmp = tmp[key[i]]
        else:
            tmp.update({key[i]: {}})
            tmp = tmp[key[i]]
    return var_dict


def fun_config_split(string):
    arr = []
    [(arr.append(m.start(0))) for m in re.finditer('!Current configuration(.+\n)+!Configuration last saved', string)]
    tmp_dict = {}
    for i in range(len(arr)):
        if i < (len(arr) - 1):
            tmp_dict.update({i: string[arr[i]:arr[i + 1]]})
        else:
            tmp_dict.update({i: string[arr[i]:]})
    return tmp_dict


def fun_int_parser(intconfig):
    global int_dict
    global lacp_dict
    for interface in re.findall('(^interface.+\n( .+\n)+!)', intconfig, re.MULTILINE):
        arr_interface = "".join(interface[:-1]).split("\n")
        if " disable" in arr_interface:
            continue
        else:
            if arr_interface[0].split()[1] == "management":
                for line in arr_interface[1:-1]:
                    if line[1:11] == "ip address":
                        ip, mask = line[12:].split()
                        int_dict = fun_dict_append([arr_interface[0].split()[3], "mgmt", "addr"], ip, int_dict)
                        int_dict = fun_dict_append([arr_interface[0].split()[3], "mgmt", "mask"], mask, int_dict)
                    elif line[1:19] == "ip default-gateway":
                        int_dict = fun_dict_append([arr_interface[0].split()[3], "mgmt", "gw"], line.split()[2],
                                                   int_dict)
                    else:
                        # print(line[1:])
                        continue
            else:
                if arr_interface[0].split()[1] == "ethernet":
                    int_dict = fun_dict_append(
                        [arr_interface[0].split()[2].split('/')[0], "port", arr_interface[0].split()[2].split('/')[1],
                         "ena"],
                        "", int_dict)
                    for line in arr_interface[1:-1]:
                        if line[1:11] == "lacp trunk":
                            # print (line[12:].split())
                            if line[12:].split()[1] == 'mode':
                                mode = line[12:].split()[2]
                            else:
                                mode = "active"
                            lacp_dict = fun_dict_append(
                                [arr_interface[0].split()[2].split('/')[0], arr_interface[0].split()[2].split('/')[1],
                                 "mode"], mode,
                                lacp_dict)
                            lacp_dict = fun_dict_append(
                                [arr_interface[0].split()[2].split('/')[0], arr_interface[0].split()[2].split('/')[1],
                                 "adminkey"], line[12:].split()[0],
                                lacp_dict)
                        # End of trunk if
                        else:
                            fun_unhandeled("interface", line)
                # end of line for
                # end of ethernet
                elif arr_interface[0].split()[1] == "ve":
                    # print (arr_interface)
                    int_dict = fun_dict_append(
                        [arr_interface[0].split()[2].split('/')[0], "if", arr_interface[0].split()[2].split('/')[1],
                         "ena"],
                        "", int_dict)
                    for line in arr_interface[1:-1]:
                        if line[1:11] == "ip address":
                            ip, mask = line[12:].split()
                            int_dict = fun_dict_append([arr_interface[0].split()[2].split('/')[0], "if",
                                                        arr_interface[0].split()[2].split('/')[1], 'addr'], ip,
                                                       int_dict)
                            int_dict = fun_dict_append([arr_interface[0].split()[2].split('/')[0], "if",
                                                        arr_interface[0].split()[2].split('/')[1], 'mask'], mask,
                                                       int_dict)
                        elif line[1:5] == "name":
                            int_dict = fun_dict_append([arr_interface[0].split()[2].split('/')[0], "if",
                                                        arr_interface[0].split()[2].split('/')[1], 'descrip'], line[6:],
                                                       int_dict)
                        else:
                            fun_unhandeled("Interface", line)
                else:
                    print(arr_interface)
    return re.sub(re.compile('(^interface.+\n( .+\n)+!)', re.MULTILINE), '', intconfig)


def fun_real_parser(realconfig):
    global real_dict
    health = ""
    for server in re.findall('(^slb server.+\n( .+\n)+!)', realconfig, re.MULTILINE):
        arr_server = "".join(server[:-1]).replace('\n	   ', ' ').split("\n")
        # print (arr_server)
        if '"' in arr_server[0]:
            name = arr_server[0].split('"')[1].replace(' ', '_')
            rip = arr_server[0].split()[4]
        else:
            name, rip = arr_server[0].split()[2:4]
        real_dict.update({name: {"ena": "", "rip": rip}})
        skip = 0
        lst_addport = []
        lst_bkp = []
        for i in range(1, len(arr_server[:-1])):
            line = arr_server[i].replace('   ', '')
            if skip:
                continue
            elif line[0:4] == "port":
                lst_addport.append(line.split()[1])
                if len(line.split()) > 3:
                    if " ".join(line.split()[3:]) == "no health-check":
                        continue
                    elif line.split()[3] == "health-check" and '"' in line and line.split('"')[1] != health:
                        print("1:" + line)
                    elif line.split()[3] == "health-check" and '"' not in line and line.split()[4] != health:
                        print("2:" + line)
            elif line[0:12] == "health-check" or line[1:13] == "health-check":
                if '"' in line:
                    health = line.split('"')[1]
                else:
                    health = line.split()[1]
                real_dict[name].update({"health": health})
            elif line[0:7] == "disable":
                if "ena" in real_dict[name]:
                    del real_dict[name]["ena"]
            elif line[0:9] == "alternate":
                lst_bkp.append(" ".join(line.split()[2:]).replace(' ', '_'))
            elif line[0:15] == "no health-check" or line[1:16] == "no health-check":
                health = "none"
            else:
                print("else:" + line)
        real_dict[name].update({'addport': lst_addport})
        if lst_bkp:
            if len(lst_bkp) == 1:
                real_dict[name].update({'backup': "r" + lst_bkp[0]})
            else:
                print(lst_bkp)
    return re.sub(re.compile(r'(^slb server.+\n( .+\n)+!)', re.MULTILINE), '', realconfig)


def fun_group_parser(group_cfg):
    global group_dict
    health = ""
    for group in re.findall('(^slb service-group.+\n( .+\n)+!)', group_cfg, re.MULTILINE):
        member_list = []
        arr_group = "".join(group[:-1]).replace('\n	   ', ' ').split("\n")
        if '"' in arr_group[0]:
            name = arr_group[0].split('"')[1].replace(' ', '_')
            # proto = arr_group[0].split('"')[2][1:]
        else:
            name = arr_group[0].split()[2]
            # proto =  arr_group[0].split()[3]
        group_dict.update({name: {}})
        for line in arr_group[1:-1]:
            line = line.replace('  ', '')
            if line[0:6] == "member":
                priority = ""
                if '"' in line:
                    junk, member, port = line.split('"')
                    member = member.replace(' ', '_')
                    if ' ' in port:
                        if len(port.split()) == 3 and port.split()[1] == 'priority':
                            priority = port.split()[2]
                        port = port.split()[0].split(':')[1]
                    elif ':' in port:
                        port = port.replace(':', '')
                else:
                    member, port = line.split()[1].split(':')
                    if len(line.split()) == 4:
                        if line.split()[2] == 'priority':
                            priority = line.split()[3]
                member_list.append(member + "#" + port)
                if priority != "":
                    fun_dict_append([name, member], priority, priority_dict)
                    group_dict[name].update({'backup': 'g' + name + '_bkp'})
            elif line[0:6] == 'method':
                metric = line.split()[1]
                group_dict[name].update({"metric": metric})
            elif line[0:12] == "health-check":
                if '"' in line:
                    health = line.split('"')[1].replace(' ', '_')
                else:
                    health = line.split()[1]
                group_dict[name].update({"health": health})
            else:
                fun_unhandeled("Group", line)
        flag1 = "S"
        for i in range(len(member_list)):
            if flag1 != "D":
                flag1 = member_list[i].split('#')[1]
                member_list[i] = member_list[i].split('#')[0]
            elif flag1 == "D" or flag1 != member_list[i].split('#')[1]:
                fun_unhandeled("Group "+name, "Found members with different port number!")
                flag1 = "D"
            if member_list[i].split('#')[0] in real_dict:
                if 'health' in real_dict[member_list[i].split('#')[0]] and health == \
                        real_dict[member_list[i].split('#')[0]]['health']:
                    real_dict[member_list[i].split('#')[0]]['health'] = 'inherit'
        if flag1 != "D":
            group_dict[name].update({'add': member_list})
    return re.sub(re.compile(r'(^slb service-group.+\n( .+\n)+!)', re.MULTILINE), '', group_cfg)


def fun_vlan_parser(vlanconfig):
    global vlan_dict
    for vlan in re.findall('(^vlan .+\n( .+\n)+!)', vlanconfig, re.MULTILINE):
        arr_vlan = "".join(vlan[:-1]).replace('\n	   ', ' ').split("\n")
        deviceid, vlanid = arr_vlan[0].split()[1].split('/')
        fun_dict_append([deviceid, vlanid], {}, vlan_dict)

        for line in arr_vlan[1:-1]:
            if line[1:6] == "name ":
                fun_dict_append([deviceid, vlanid, 'name'], '"' + line.replace(' name ', '').replace('"', '') + '"',
                                vlan_dict)
            elif line[1:17] == "router-interface":
                int_dict[deviceid]['if'][str(line.split()[2])].update({"vlan": vlanid})
            elif line[1:7] == "tagged":
                tmp = line.split()
                if len(tmp) == 5:
                    vlanadd = ''
                    for i in range(int(tmp[2]), int(tmp[4]) + 1):
                        vlanadd = vlanadd + " " + str(i)
                    fun_dict_append([deviceid, vlanid, 'def'], vlanadd, vlan_dict)
                else:
                    fun_unhandeled("VLAN", line)
            else:
                fun_unhandeled("VLAN", line)
    return re.sub(re.compile(r'(^vlan .+\n( .+\n)+!)', re.MULTILINE), '', vlanconfig)


def fun_route_parser(routeconfig):
    global route_dict
    global gw_dict
    c = 0
    for route in re.findall('(^ip route.+)', routeconfig, re.MULTILINE):
        junk, junk, dst, mask, gw, junk, deviceid = route.split()
        # print ("dst="+dst+", mask="+mask)
        if dst == '0.0.0.0' and mask == '/0':
            fun_dict_append([deviceid, gw], "", gw_dict)
        else: 
            fun_dict_append([deviceid, dst + mask], gw, route_dict)
    return re.sub(re.compile(r'(^ip route.+)', re.MULTILINE), '', routeconfig)


def fun_health_parser(healthconfig):
    global health_dict
    for health in re.findall('(^health monitor.+\n( .+\n)+!)', healthconfig, re.MULTILINE):
        arr_health = "".join(health[:-1]).splitlines()
        if '"' in arr_health[0]:
            name = arr_health[0].split('"')[1].replace(' ', '_')
        else:
            name = arr_health[0].split()[2]
        health_dict.update({name: {}})
        for line in arr_health[1:-1]:
            if line[1:7] == "method":
                if '"' in line:
                    start = line.find('"', 0)
                    while True:
                        index = line.find('"', start + 1)
                        if index == -1:
                            break
                        else:
                            line = line.replace(line[start + 1:index],
                                                line[start + 1:index].replace(' ', '$$!!Rad!!$$'))
                        start = index
                arr_line = line.split()
                health_dict[name].update({'hctype': arr_line[1]})
                arr_line = iter(arr_line[2:])
                for x in arr_line:
                    if x == 'port':
                        health_dict[name].update({'dport': next(arr_line)})
                    elif x == "url":
                        health_dict[name].update(
                            {'http/method': next(arr_line) + "/..", 'http/path': "\"" + next(arr_line) + "\"" + "/.."})
                    elif x == "expect":
                        tmp = next(arr_line)
                        if tmp == 'response-code':
                            tmp = next(arr_line)
                            if tmp[0] != '"':
                                tmp = '"' + tmp + '"'
                        else:
                            if tmp[0] != '"':
                                tmp = '200 incl "' + tmp + '"'
                            else:
                                tmp = '200 incl ' + tmp

                        health_dict[name].update({'http/resp': tmp.replace('$$!!Rad!!$$', ' ') + "/.."})
                    elif x == "host":
                        health_dict[name].update({'http/host': next(arr_line)+"/.."})
                    else:
                        print(x)
    return re.sub(re.compile(r'(^health monitor.+\n( .+\n)+!)', re.MULTILINE), '', healthconfig)


def fun_natpool_parser(natpoolconfig):
    global nwclass_dict
    for natpool in re.findall('(^ip nat pool.+)', natpoolconfig, re.MULTILINE):
        arr_natpool = natpool.split()
        nwclass_dict.update({arr_natpool[3]: {'start': arr_natpool[4], 'end': arr_natpool[5]}})
        fun_unhandeled("Nat Pool", natpool[natpool.find(arr_natpool[6]):])
    return re.sub(re.compile(r'(^ip nat pool.+)', re.MULTILINE), '', natpoolconfig)


def fun_virt_parser(virtconfig):
    global virt_dict
    global vip_list
    for virt in re.findall('(^slb virtual-server.+\n( .+\n)+!)', virtconfig, re.MULTILINE):
        str_virt = ''.join(virt[:-1])
        for line in str_virt.replace('  ', '').splitlines():
            if '"' in line:
                start = line.find('"', 0)
                while True:
                    index = line.find('"', start + 1)
                    if index == -1:
                        break
                    else:
                        str_virt = str_virt.replace(line[start + 1:index],
                                                    line[start + 1:index].replace(' ', '$$!!Rad!!$$'))
                        index += len('$$!!Rad!!$$')
                    start = index
        arr_virt = str_virt.split()
        name=arr_virt[2].replace('$$!!Rad!!$$', '_').replace('"','')
        virt_dict.update({name: {'vip': arr_virt[3]}})
        vip_list.append(arr_virt[3])
        for service in re.findall('(^ {3}port .+\n( .+\n)+!)', str_virt, re.MULTILINE):
            str_service = ''.join(service[:-1])
            # print(str_service[0])
            arr_service = str_service.split()
            arr_service = iter(arr_service)
            for x in arr_service:
                if x == 'port':
                    srvcport = next(arr_service)
                    srvcproto = next(arr_service)
                    if srvcproto in ['tcp','udp']:
                        if srvcport in reservedprort_dict:
                            # print("srvcport="+srvcport+",srvcproto="+srvcproto+", Changing proto to: "+ reservedprort_dict[srvcport])
                            srvcproto = reservedprort_dict[srvcport]
                        else: 
                            srvcproto = 'basic-slb'
                    if 'service' in virt_dict[name]:
                        virt_dict[name]['service'].update({srvcport: {'protocol': srvcproto}})
                    else:
                        virt_dict[name].update({'service': {srvcport: {'protocol': srvcproto}}})
                elif x == 'service-group':
                    virt_dict[name]['service'][srvcport].update({'group': next(arr_service).replace('$$!!Rad!!$$', '_')})
                elif x == 'source-nat':
                    tmp = next(arr_service)
                    if tmp == 'pool':
                        virt_dict[name]['service'][srvcport].update({'pip': {'mode': 'nwclss', 'nwclss v4': next(arr_service)+' persist d'}})
                    else:
                        fun_unhandeled("PIP", tmp)
                elif x == 'name':
                    descrip=next(arr_service).replace('$$!!Rad!!$$', ' ').replace('"','')
                    virt_dict[name]['service'][srvcport].update({'name': '"'+descrip+'"'})
                elif x == 'ha-conn-mirror':
                    virt_dict[name]['service'][srvcport].update({'mirror': "ena"})
                elif x == 'use-rcv-hop-for-resp':
                    virt_dict[name].update({'rtsrcmac': "ena"})
                elif x == '!':
                    continue
                elif x == 'disable':
                    # print("Service %s in virt %s should be disabled." % (srvcport, name))
                    continue
                elif x == "template":
                    tmpl_type = next(arr_service)
                    tmpl_name = next(arr_service)
                    if tmpl_name in tmpl_dict and tmpl_type == tmpl_dict[tmpl_name]['type']:
                        virt_dict[name].update({'tmpl': tmpl_dict})
                    else:
                        fun_unhandeled("Virt \"" + name, x + '\",' + tmpl_name + ',' + tmpl_type)
                else:
                    fun_unhandeled("Virt \"" + name + "\"", x)
                #
    return re.sub(re.compile(r'(^slb virtual-server.+\n( .+\n)+!)', re.MULTILINE), '', virtconfig)


def fun_template_parser(tmplconfig):
    global tmpl_dict
    for tmpl in re.findall('(^slb template .+\n?( .+\n)+!)', tmplconfig, re.MULTILINE):
        str_tmpl = ''.join(tmpl[:-1])
        arr_tmpl = str_tmpl.split()
        tmpl_type, tmpl_name = arr_tmpl[2:4]
        tmpl_dict.update({tmpl_name: {'type': tmpl_type}})
        str_tmp2 = str_tmpl.splitlines()[:-1]
        if len(str_tmp2) == 1:
            if arr_tmpl[4] == "src-persisitency":
                tmpl_dict[tmpl_name].update({'pbind': 'clientip'})
        else:
            for line in str_tmp2:
                if tmpl_type == "http" and line.replace(' ', '') == 'insert-client-ip':
                    tmpl_dict[tmpl_name].update({'xff': 'ena'})
                elif line.split()[0] == 'idle-timeout':
                    tmpl_dict[tmpl_name].update({'ptmout': int(int(line.split()[1]) / 60)})
                else:
                    fun_unhandeled("Template \"" + tmpl_name + "\"", line)

    return re.sub(re.compile(r'(^slb template .+\n( .+\n)+!)', re.MULTILINE), '', tmplconfig)


def fun_vrrp_parser(vrrpconfig):
    global vip_list
    global float_dict
    for vrrp in re.findall('(^vrrp-a vrid .+\n( .+\n)+!)', vrrpconfig, re.MULTILINE):
        # str_vrrp = ''.join(vrrp[:-1]).split()
        # vrid = arr_vrrp[2]
        for line in ''.join(vrrp[:-1]).splitlines()[1:-1]:
            if line.split()[0] == 'floating-ip':
                tmp = line.split()
                if tmp[1] not in vip_list:
                    float_dict.update({tmp[1]: {}})
            else:
                fun_unhandeled("VRRP", line)
    return re.sub(re.compile(r'(^vrrp-a vrid .+\n( .+\n)+!)', re.MULTILINE), '', vrrpconfig)


def fun_arp_parser(arpcfg):
    global arp_dict
    for arp in re.findall('(^arp .+\n!)', arpcfg, re.MULTILINE):
        arr_arp = ''.join(arp[:-1]).split()
        iter_arp = iter(arr_arp)
        for item in iter_arp:
            if item == "arp":
                ip = next(iter_arp)
                mac = next(iter_arp).replace('.', '')
                tmp_arr = []
                for i in range(len(mac)):
                    if i != 0 and i % 2 and i != len(mac) - 1:
                        tmp_arr.append(mac[i] + ":")
                    else:
                        tmp_arr.append(mac[i])
                mac = "".join(tmp_arr)
            elif item == "interface":
                next(iter_arp)
                port = next(iter_arp)
            elif item == "vlan":
                vlan = next(iter_arp)
            elif item == "device":
                arp_dict.update({next(iter_arp): {ip: {'mac': mac, 'port': port, 'vlan': vlan}}})
            else:
                print(item)

    return re.sub(re.compile(r'(^arp .+\n!)', re.MULTILINE), '', arpcfg)


def fun_sysconfig_parser(general_conf):
    global ntp_list
    global hostname_dict
    # ntp server
    index = 0
    while index != -1:
        index = general_conf.find("ntp server")
        if index != -1:
            ntp_line = general_conf[index:general_conf.find("\n", index)]
            general_conf = general_conf.replace(ntp_line, '')
            ntp_list.append(ntp_line.split()[2])
    # hostname
    index = 0
    while index != -1:
        index = general_conf.find("hostname ")
        if index != -1:
            hostname_line = general_conf[index:general_conf.find("\n", index)]
            general_conf = general_conf.replace(hostname_line, '')
            if " device " in hostname_line:
                hostname_dict.update({hostname_line.split()[-1]: hostname_line[9:hostname_line.find("device") - 1]})
            else:
                fun_unhandeled("hostname", hostname_line)
    return general_conf


def alteon_config_print():
    for i in range(1, len(int_dict) + 1):
        device = str(i)
        out.write("\n" + "#" * 19 + "\n")
        out.write("## Device ID = " + device + " ##\n")
        out.write("#" * 19 + "\n")
        if device in int_dict:
            for item in int_dict[device]:
                flag = 0
                if item == 'if':
                    cfgstring = "\n/c/l3/if "
                    flag = 1
                elif item == 'port':
                    cfgstring = "\n/c/port "
                    flag = 1
                if flag:
                    if_counter = 0
                    for if_id in int_dict[device][item]:
                        if_counter += 1
                        out.write(cfgstring + str(if_counter) + "\n")
                        for cfg in int_dict[device][item][if_id]:
                            out.write("\t" + cfg + " " + int_dict[device][item][if_id][cfg] + "\n")
                else:
                    if item == 'mgmt':
                        out.write("\n/c/sys/mmgmt\n")
                        for cfg in int_dict[device][item]:
                            out.write("\t" + cfg + " " + int_dict[device][item][cfg] + "\n")

        if device in lacp_dict:
            for port in lacp_dict[device]:
                out.write("\n/c/l2/lacp/port " + port + "\n")
                for cfg in lacp_dict[device][port]:
                    out.write("\t" + cfg + " " + lacp_dict[device][port][cfg] + "\n")

        if device in vlan_dict:
            for vlan in vlan_dict[device]:
                out.write("\n/c/l2/vlan " + vlan + "\n")
                for cfg in vlan_dict[device][vlan]:
                    out.write("\t" + cfg + " " + vlan_dict[device][vlan][cfg] + "\n")

        if device in route_dict:
            out.write("\n/c/l3/route/ip4\n")
            for route in route_dict[device]:
                net, mask = route.split('/')
                out.write("\tadd " + net + " " + prefix_mask_dict[mask] + " " + route_dict[device][route] + "\n")

        if device in gw_dict:
            c = 0
            for gw in gw_dict[device]:
                c += 1
                out.write("\n/c/l3/gw "+str(c)+"\n")
                out.write("\tena\n\taddr " + gw + "\n")

        if device in arp_dict:
            out.write("/c/l3/arp/static\n")
            for ip in arp_dict[device]:
                out.write("\tadd " + ip + " " + arp_dict[device][ip]['mac'] + " " + arp_dict[device][ip]['port'] + " " +
                          arp_dict[device][ip]['vlan'] + "\n")

    for real in real_dict:
        out.write("\n/c/slb/real " + real + "\n")
        for cfg in real_dict[real]:
            if cfg == "addport":
                continue
            else:
                out.write("\t" + cfg + " " + real_dict[real][cfg] + "\n")

    for group in group_dict:
        out.write("\n/c/slb/group " + group + "\n")
        flag = 0
        tmp = ""
        for cfg in group_dict[group]:
            if cfg == "add":
                for item in group_dict[group]['add']:
                    if group in priority_dict and item in priority_dict[group]:
                        flag = 1
                    else:
                        out.write("\tadd " + item + "\n")
            else:
                out.write("\t" + cfg + " " + group_dict[group][cfg] + "\n")
                tmp += "\t" + cfg + " " + group_dict[group][cfg] + "\n"
        if flag:
            out.write("/c/slb/group " + group + "_bkp\n")
            for item in priority_dict[group]:
                out.write("\t add " + item + "\n")

    for nwclass in nwclass_dict:
        out.write("\n/c/slb/nwclss " + nwclass + "\n\ttype \"address\"\n\tipver v4\n")
        out.write("/c/slb/nwclss " + nwclass + "/network 1\n")
        out.write("\tnet range " + nwclass_dict[nwclass]['start'] + " " + nwclass_dict[nwclass]['end'] + " include\n")

    for item in health_dict:
        out.write("\n/c/slb/advhc/health " + item + " " + health_dict[item]['hctype'] + "\n")
        for cfg in health_dict[item]:
            if cfg != "hctype":
                out.write("\t" + cfg + " " + health_dict[item][cfg] + "\n")

    for item in virt_dict:
        strtmpl = ""
        out.write("\n/c/slb/virt " + item)
        for attrib in virt_dict[item]:
            if attrib == 'service':
                continue
            elif attrib == 'tmpl':
                for tmpl in virt_dict[item][attrib]:
                    if virt_dict[item][attrib][tmpl]['type'] not in ["persist", "tcp"]:
                        strtmpl += ("\n/"+virt_dict[item][attrib][tmpl]['type'])
                    for tmplattrib in virt_dict[item][attrib][tmpl]:
                        if tmplattrib != 'type':
                            strtmpl += ("\n\t" + tmplattrib + " " + str(virt_dict[item][attrib][tmpl][tmplattrib]))
                    if virt_dict[item][attrib][tmpl]['type'] not in ["persist", "tcp"]:
                        strtmpl += ("\n/..")
            else:
                out.write("\n\t"+attrib+" "+virt_dict[item][attrib])
        for service in virt_dict[item]['service']:
            strpip = ""
            strsvc = (
                "\n/c/slb/virt " + item + "/service " + service + " " + virt_dict[item]['service'][service]['protocol'])
            for serviceattrib in virt_dict[item]['service'][service]:
                if serviceattrib == 'protocol':
                    continue
                elif serviceattrib == 'pip':
                    strpip = (
                        "\n/c/slb/virt " + item + "/service " + service + " " + virt_dict[item]['service'][service][
                            'protocol'] + "/pip")
                    for pip in virt_dict[item]['service'][service][serviceattrib]:
                        strpip +=  ("\n\t" + pip + " " + virt_dict[item]['service'][service][serviceattrib][pip])
                else:
                    strsvc += ("\n\t" + serviceattrib + " " + virt_dict[item]['service'][service][serviceattrib])
            out.write(strsvc + strtmpl + strpip)


config_dict = fun_config_split(file.read())
new_config = []
out_counter = 0
for c in config_dict.values():
    out_counter += 1
    out = open(project_name+"_cfg_out_" + str(out_counter) + ".txt", 'w+')
    leftovers = open(project_name+"_leftovers_" + str(out_counter) + ".txt", 'w+')
    c = fun_int_parser(c)
    c = fun_real_parser(c)
    c = fun_group_parser(c)
    c = fun_vlan_parser(c)
    c = fun_route_parser(c)
    c = fun_health_parser(c)
    c = fun_natpool_parser(c)
    c = fun_template_parser(c)
    c = fun_virt_parser(c)
    c = fun_vrrp_parser(c)
    c = fun_arp_parser(c)
    c = fun_sysconfig_parser(c)

    # end of parsing, write output + leftovers.
    alteon_config_print()
    c = fun_clear_cfg_and_dicts(c)
    leftovers.write(c)
    out.close()
    leftovers.close()
